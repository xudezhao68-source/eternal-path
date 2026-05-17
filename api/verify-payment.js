// api/verify-payment.js
// Vercel Serverless Function — 验证 PayPal 付款并返回解锁 token

const crypto = require('crypto');

// 生成解锁 token（基于订单ID + 密钥，防伪造）
function generateToken(orderId) {
  const secret = process.env.UNLOCK_SECRET || 'fallback-secret-change-this';
  return crypto
    .createHmac('sha256', secret)
    .update(orderId)
    .digest('hex')
    .slice(0, 32);
}

// 向 PayPal 验证订单真实性
async function verifyPayPalOrder(orderId) {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    console.error('Missing PayPal credentials');
    return false;
  }

  // 获取 PayPal access token
  const authRes = await fetch('https://api-m.paypal.com/v1/oauth2/token', {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  if (!authRes.ok) {
    console.error('PayPal auth failed:', await authRes.text());
    return false;
  }

  const { access_token } = await authRes.json();

  // 查询订单详情
  const orderRes = await fetch(`https://api-m.paypal.com/v2/checkout/orders/${orderId}`, {
    headers: { 'Authorization': `Bearer ${access_token}` },
  });

  if (!orderRes.ok) {
    console.error('PayPal order fetch failed:', await orderRes.text());
    return false;
  }

  const order = await orderRes.json();

  // 验证：订单状态必须是 COMPLETED，金额必须是 4.90 USD
  const isCompleted = order.status === 'COMPLETED';
  const unit = order.purchase_units?.[0];
  const amount = unit?.amount;
  const isCorrectAmount =
    amount?.currency_code === 'USD' &&
    parseFloat(amount?.value) >= 4.89; // 允许小数点误差

  console.log(`Order ${orderId}: status=${order.status}, amount=${amount?.value} ${amount?.currency_code}`);

  return isCompleted && isCorrectAmount;
}

module.exports = async function handler(req, res) {
  // 只允许 POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // CORS 头（允许你的域名调用）
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  const { orderId } = req.body;

  if (!orderId || typeof orderId !== 'string' || orderId.length > 100) {
    return res.status(400).json({ error: 'Invalid orderId' });
  }

  try {
    const isValid = await verifyPayPalOrder(orderId);

    if (isValid) {
      const token = generateToken(orderId);
      return res.status(200).json({ success: true, token });
    } else {
      return res.status(402).json({ success: false, error: 'Payment not verified' });
    }
  } catch (err) {
    console.error('Verification error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
};
