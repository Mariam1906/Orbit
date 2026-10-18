const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');

const DEFAULT_BUCKET = 'invoices';
const USDC_DECIMALS = 7;

const explorerUrl = (txHash, network = process.env.STELLAR_EXPERT_NETWORK || 'testnet') =>
    `https://stellar.expert/explorer/${encodeURIComponent(network)}/tx/${encodeURIComponent(txHash)}`;

const formatUsdc = (units) => {
    const value = BigInt(String(units));
    const whole = value / (10n ** BigInt(USDC_DECIMALS));
    const fraction = (value % (10n ** BigInt(USDC_DECIMALS))).toString().padStart(USDC_DECIMALS, '0').replace(/0+$/, '');
    return `${whole}${fraction ? `.${fraction}` : ''} USDC`;
};

const generateReceiptPdf = async ({ invoiceNumber, merchantName, customerWallet, planName, amountUsdcUnits, settledAt, txHash, ledgerSequence }) => {
    const transactionUrl = explorerUrl(txHash);
    const qr = await QRCode.toBuffer(transactionUrl, { errorCorrectionLevel: 'M', margin: 1, width: 160 });
    const document = new PDFDocument({ margin: 54, size: 'A4', info: { Title: `Orbit receipt ${invoiceNumber}` } });
    const chunks = [];
    document.on('data', (chunk) => chunks.push(chunk));
    const complete = new Promise((resolve, reject) => {
        document.on('end', () => resolve(Buffer.concat(chunks)));
        document.on('error', reject);
    });

    document.fillColor('#171717').fontSize(25).text('Orbit', { continued: true }).fillColor('#2563eb').text(' receipt');
    document.moveDown(0.3).fillColor('#525252').fontSize(10).text(`Invoice ${invoiceNumber}`);
    document.moveDown(1.5).fillColor('#171717').fontSize(16).text('Payment settled');
    document.moveDown(0.5).fontSize(11);
    const rows = [
        ['Merchant', merchantName],
        ['Subscriber', customerWallet],
        ['Plan', planName],
        ['Amount', formatUsdc(amountUsdcUnits)],
        ['Settled at', new Date(settledAt).toISOString()],
        ['Transaction hash', txHash],
        ['Ledger', ledgerSequence == null ? 'Unavailable' : String(ledgerSequence)],
    ];
    for (const [label, value] of rows) {
        document.fillColor('#525252').text(`${label}: `, { continued: true }).fillColor('#171717').text(value);
    }
    document.moveDown(1.3).fillColor('#525252').fontSize(9).text('Verify this settlement on Stellar Expert:');
    document.fillColor('#2563eb').text(transactionUrl, { link: transactionUrl, underline: true });
    document.image(qr, 54, 570, { width: 112 }).fillColor('#525252').fontSize(8).text('Scan to verify on Stellar Expert', 54, 688, { width: 140 });
    document.end();
    return complete;
};

const invoiceNumber = (id) => `ORB-${String(id).replace(/-/g, '').slice(0, 12).toUpperCase()}`;

function createInvoiceService({ supabase, bucket = process.env.INVOICE_STORAGE_BUCKET || DEFAULT_BUCKET, logger = console } = {}) {
    if (!supabase) throw new Error('supabase is required');

    async function createForSettledPayment({ payment, merchant, plan, subscription, ledgerSequence = null }) {
        const draft = {
            merchant_id: payment.merchant_id,
            payment_transaction_id: payment.id,
            subscription_id: payment.subscription_id,
            invoice_number: invoiceNumber(payment.id),
            status: 'processing',
            transaction_hash: payment.tx_hash,
            ledger_sequence: ledgerSequence,
            settled_at: payment.settled_at,
        };
        const { data: invoice, error } = await supabase.from('invoices').insert([draft]).select().single();
        if (error?.code === '23505') return { duplicate: true };
        if (error) throw error;

        try {
            const pdf = await generateReceiptPdf({
                invoiceNumber: invoice.invoice_number,
                merchantName: merchant.name,
                customerWallet: subscription.customer_wallet_address,
                planName: plan.name,
                amountUsdcUnits: payment.amount_usdc_units,
                settledAt: payment.settled_at,
                txHash: payment.tx_hash,
                ledgerSequence,
            });
            const storagePath = `${payment.merchant_id}/${invoice.id}.pdf`;
            const { error: uploadError } = await supabase.storage.from(bucket).upload(storagePath, pdf, {
                contentType: 'application/pdf', upsert: false,
            });
            if (uploadError) throw uploadError;
            const { data: finalized, error: finalizeError } = await supabase.from('invoices')
                .update({ status: 'ready', storage_bucket: bucket, storage_path: storagePath, generated_at: new Date().toISOString() })
                .eq('id', invoice.id).select().single();
            if (finalizeError) throw finalizeError;
            return { invoice: finalized };
        } catch (generationError) {
            logger.error('Invoice generation failed:', generationError);
            await supabase.from('invoices').update({ status: 'failed', failure_reason: generationError.message }).eq('id', invoice.id);
            return { error: generationError };
        }
    }

    async function signedDownload(invoice, expiresIn = 60) {
        if (invoice.status !== 'ready' || !invoice.storage_path) {
            const error = new Error('Invoice is not available yet');
            error.statusCode = 409;
            throw error;
        }
        const { data, error } = await supabase.storage.from(invoice.storage_bucket || bucket)
            .createSignedUrl(invoice.storage_path, expiresIn);
        if (error) throw error;
        return data.signedUrl;
    }

    return { createForSettledPayment, signedDownload };
}

function registerInvoiceRoutes(app, getSupabase, authenticateMerchant) {
    const getService = () => app.locals.invoiceService || createInvoiceService({ supabase: getSupabase() });
    const list = async (req, res, next, subscriptionId = null) => {
        try {
            let query = getSupabase().from('invoices').select('id, subscription_id, invoice_number, status, transaction_hash, ledger_sequence, settled_at, generated_at, created_at')
                .eq('merchant_id', req.merchant.id);
            if (subscriptionId) query = query.eq('subscription_id', subscriptionId);
            const { data, error } = await query.order('settled_at', { ascending: false });
            if (error) throw error;
            res.json({ invoices: data || [] });
        } catch (error) { next(error); }
    };
    app.get('/invoices', authenticateMerchant, (req, res, next) => list(req, res, next));
    app.get('/subscriptions/:id/invoices', authenticateMerchant, (req, res, next) => list(req, res, next, req.params.id));
    app.get('/invoices/:id/download', authenticateMerchant, async (req, res, next) => {
        try {
            const { data: invoice, error } = await getSupabase().from('invoices').select('*')
                .eq('id', req.params.id).eq('merchant_id', req.merchant.id).maybeSingle();
            if (error) throw error;
            if (!invoice) return res.status(404).json({ error: 'Invoice not found' });
            const url = await getService().signedDownload(invoice);
            res.set('Cache-Control', 'private, no-store');
            res.json({ url, expires_in: 60 });
        } catch (error) {
            if (error.statusCode) return res.status(error.statusCode).json({ error: error.message });
            next(error);
        }
    });
}

module.exports = { explorerUrl, formatUsdc, generateReceiptPdf, createInvoiceService, registerInvoiceRoutes };
