// api/validate-token.js
// 验证前端传来的 token 是否合法（二次校验，防止伪造）

const crypto = require('crypto');

function generateToken(orderId) {
  const secret = process.env.UNLOCK_SECRET || 'fallback-secret-change-this';
  return crypto
    .createHmac('sha256', secret)
    .update(orderId)
    .digest('hex')
    .slice(0, 32);
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  const { token, orderId } = req.body;

  if (!token || !orderId) {
    return res.status(400).json({ valid: false });
  }

  const expected = generateToken(orderId);
  const isValid = crypto.timingSafeEqual(
    Buffer.from(token, 'hex'),
    Buffer.from(expected, 'hex')
  );

  return res.status(200).json({ valid: isValid });
};
