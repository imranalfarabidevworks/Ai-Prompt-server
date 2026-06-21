// const dns = require('node:dns');
const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');

// dns.setServers(['8.8.8.8', '8.8.4.4']);

const app = express();
const port = process.env.PORT || 5000;

const allowedOrigins = [
  process.env.CLIENT_URL || 'https://ai-prompt-client.vercel.app',
  'http://localhost:3000',
];
app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json());
app.use(cookieParser());

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

const signToken = (payload) => jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

const setTokenCookie = (res, token) => {
  res.cookie('ph_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

// ─── Safe ObjectId helper ─────────────────────

const toObjectId = (id) => {
  try { return new ObjectId(id); } catch { return null; }
};

const verifyToken = (req, res, next) => {
  let token = null;
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) token = auth.split(' ')[1];
  else if (req.cookies?.ph_token) token = req.cookies.ph_token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({ message: 'Invalid token' }); }
};

const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  next();
};

const verifyCreatorOrAdmin = (req, res, next) => {
  if (!['creator', 'admin'].includes(req.user?.role)) return res.status(403).json({ message: 'Forbidden' });
  next();
};

async function run() {
  await client.connect();
  console.log('✅ MongoDB connected');

  const db = client.db('prompthive');
  const usersCol    = db.collection('users');
  const promptsCol  = db.collection('prompts');
  const reviewsCol  = db.collection('reviews');
  const reportsCol  = db.collection('reports');
  const paymentsCol = db.collection('payments');

  
  // AUTH
  
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { name, email, photoURL, password } = req.body;
      if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });
      if (await usersCol.findOne({ email })) return res.status(409).json({ message: 'Email already registered' });
      const hashed = await bcrypt.hash(password, 10);
      const result = await usersCol.insertOne({
        name, email, photoURL: photoURL || '', password: hashed,
        role: 'user', isPremium: false, promptCount: 0, bookmarks: [], createdAt: new Date(),
      });
      const payload = { _id: result.insertedId.toString(), name, email, photoURL: photoURL || '', role: 'user', isPremium: false };
      const token = signToken(payload);
      setTokenCookie(res, token);
      res.status(201).json({ token, user: payload });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await usersCol.findOne({ email });
      if (!user) return res.status(404).json({ message: 'User not found' });
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ message: 'Incorrect password' });
      const payload = { _id: user._id.toString(), name: user.name, email: user.email, photoURL: user.photoURL || '', role: user.role, isPremium: !!user.isPremium };
      const token = signToken(payload);
      setTokenCookie(res, token);
      res.json({ token, user: payload });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.post('/api/auth/google', async (req, res) => {
    try {
      const { name, email, photoURL } = req.body;
      let user = await usersCol.findOne({ email });
      if (!user) {
        const result = await usersCol.insertOne({
          name, email, photoURL: photoURL || '', password: '',
          role: 'user', isPremium: false, promptCount: 0, bookmarks: [], createdAt: new Date(),
        });
        user = { _id: result.insertedId, name, email, photoURL: photoURL || '', role: 'user', isPremium: false };
      }
      const payload = { _id: user._id.toString(), name: user.name, email: user.email, photoURL: user.photoURL || '', role: user.role, isPremium: !!user.isPremium };
      const token = signToken(payload);
      setTokenCookie(res, token);
      res.json({ token, user: payload });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.get('/api/auth/me', verifyToken, async (req, res) => {
    try {
      const oid = toObjectId(req.user._id);
      if (!oid) return res.status(400).json({ message: 'Invalid user id' });
      const user = await usersCol.findOne({ _id: oid }, { projection: { password: 0 } });
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json({ user: { ...user, _id: user._id.toString() } });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('ph_token');
    res.json({ message: 'Logged out' });
  });


  // PROMPTS
  

  // GET all prompts
  app.get('/api/prompts', async (req, res) => {
    try {
      const { search, category, aiTool, difficulty, sort, page = 1, limit = 9 } = req.query;
      const query = { status: 'approved' };
      if (search) query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { tags: { $elemMatch: { $regex: search, $options: 'i' } } },
        { aiTool: { $regex: search, $options: 'i' } },
      ];
      if (category) query.category = category;
      if (aiTool) query.aiTool = aiTool;
      if (difficulty) query.difficulty = difficulty;
      const sortOption = sort === 'popular' ? { rating: -1 } : sort === 'copied' ? { copyCount: -1 } : { createdAt: -1 };
      const skip = (parseInt(page) - 1) * parseInt(limit);
      const [prompts, total] = await Promise.all([
        promptsCol.find(query).sort(sortOption).skip(skip).limit(parseInt(limit)).toArray(),
        promptsCol.countDocuments(query),
      ]);
      res.json({ prompts, total });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // GET my prompts
  app.get('/api/prompts/mine', verifyToken, async (req, res) => {
    try {
      const prompts = await promptsCol.find({ creatorEmail: req.user.email }).sort({ createdAt: -1 }).toArray();
      res.json(prompts);
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // GET single prompt
  app.get('/api/prompts/:id', async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      // ObjectId
      const query = oid ? { $or: [{ _id: oid }, { _id: req.params.id }] } : { _id: req.params.id };
      const prompt = await promptsCol.findOne(oid ? { _id: oid } : { _id: req.params.id });
      if (!prompt) return res.status(404).json({ message: 'Prompt not found' });
      // reviews store 
      const reviews = await reviewsCol.find({ promptId: req.params.id }).sort({ createdAt: -1 }).limit(20).toArray();
      res.json({ ...prompt, _id: prompt._id.toString(), reviews });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // POST add prompt
  app.post('/api/prompts', verifyToken, async (req, res) => {
    try {
      if (req.user.role === 'user' && !req.user.isPremium) {
        const count = await promptsCol.countDocuments({ creatorEmail: req.user.email });
        if (count >= 3) return res.status(403).json({ message: 'Free users can only add 3 prompts. Upgrade to Premium.' });
      }
      const prompt = {
        ...req.body,
        creatorEmail: req.user.email,
        creatorName: req.user.name,
        creatorAvatar: (req.user.name || 'U').slice(0, 2).toUpperCase(),
        status: 'pending',
        copyCount: 0, rating: 0, reviewCount: 0, bookmarkCount: 0,
        createdAt: new Date(),
      };
      const result = await promptsCol.insertOne(prompt);
      res.status(201).json({ _id: result.insertedId.toString(), ...prompt });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // PUT update prompt
  app.put('/api/prompts/:id', verifyToken, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      const prompt = await promptsCol.findOne({ _id: oid });
      if (!prompt) return res.status(404).json({ message: 'Not found' });
      if (prompt.creatorEmail !== req.user.email && req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
      const { _id, creatorEmail, status, copyCount, createdAt, ...updates } = req.body;
      await promptsCol.updateOne({ _id: oid }, { $set: { ...updates, updatedAt: new Date() } });
      res.json({ message: 'Updated' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // DELETE prompt
  app.delete('/api/prompts/:id', verifyToken, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      const prompt = await promptsCol.findOne({ _id: oid });
      if (!prompt) return res.status(404).json({ message: 'Not found' });
      if (prompt.creatorEmail !== req.user.email && req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
      await promptsCol.deleteOne({ _id: oid });
      res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  
  app.patch('/api/prompts/:id/copy', async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (oid) await promptsCol.updateOne({ _id: oid }, { $inc: { copyCount: 1 } });
      res.json({ message: 'Copy count updated' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  
  app.post('/api/prompts/:id/bookmark', verifyToken, async (req, res) => {
    try {
      const userOid = toObjectId(req.user._id);
      if (!userOid) return res.status(400).json({ message: 'Invalid user id' });
      const user = await usersCol.findOne({ _id: userOid });
      const bookmarks = user.bookmarks || [];
      const idx = bookmarks.indexOf(req.params.id);
      if (idx === -1) {
        await usersCol.updateOne({ _id: userOid }, { $push: { bookmarks: req.params.id } });
        const promptOid = toObjectId(req.params.id);
        if (promptOid) await promptsCol.updateOne({ _id: promptOid }, { $inc: { bookmarkCount: 1 } });
        res.json({ bookmarked: true });
      } else {
        await usersCol.updateOne({ _id: userOid }, { $pull: { bookmarks: req.params.id } });
        const promptOid = toObjectId(req.params.id);
        if (promptOid) await promptsCol.updateOne({ _id: promptOid }, { $inc: { bookmarkCount: -1 } });
        res.json({ bookmarked: false });
      }
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  
  app.post('/api/prompts/:id/review', verifyToken, async (req, res) => {
    try {
      const { rating, comment } = req.body;
      if (!rating || !comment) return res.status(400).json({ message: 'Rating and comment required' });

      const promptId = req.params.id; 

  
      await reviewsCol.insertOne({
        promptId,              
        userId: req.user._id,
        userName: req.user.name,
        userEmail: req.user.email,
        rating: parseInt(rating),
        comment: comment.trim(),
        createdAt: new Date(),
      });

    
      const agg = await reviewsCol.aggregate([
        { $match: { promptId } },
        { $group: { _id: null, avg: { $avg: '$rating' }, count: { $sum: 1 } } },
      ]).toArray();

      if (agg.length) {
        const newRating = Math.round(agg[0].avg * 10) / 10;
        const newCount = agg[0].count;
        const oid = toObjectId(promptId);
        if (oid) {
          await promptsCol.updateOne({ _id: oid }, { $set: { rating: newRating, reviewCount: newCount } });
        }
      }

      res.status(201).json({ message: 'Review submitted successfully' });
    } catch (err) {
      console.error('Review error:', err.message);
      res.status(500).json({ message: err.message });
    }
  });

  // POST report
  app.post('/api/prompts/:id/report', verifyToken, async (req, res) => {
    try {
      await reportsCol.insertOne({
        promptId: req.params.id,
        reporterEmail: req.user.email,
        reason: req.body.reason,
        description: req.body.description || '',
        createdAt: new Date(),
      });
      res.status(201).json({ message: 'Report submitted' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // ══════════════════════════
  // USER
  // ══════════════════════════
  app.get('/api/users/bookmarks', verifyToken, async (req, res) => {
    try {
      const oid = toObjectId(req.user._id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      const user = await usersCol.findOne({ _id: oid });
      const ids = (user.bookmarks || []).map(id => toObjectId(id)).filter(Boolean);
      const prompts = ids.length > 0 ? await promptsCol.find({ _id: { $in: ids } }).toArray() : [];
      res.json(prompts);
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.get('/api/users/reviews', verifyToken, async (req, res) => {
    try {
      const reviews = await reviewsCol.find({ userEmail: req.user.email }).sort({ createdAt: -1 }).toArray();
      res.json(reviews);
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // ══════════════════════════
  // PAYMENT
  // ══════════════════════════
  app.post('/api/payment/success', verifyToken, async (req, res) => {
    try {
      const oid = toObjectId(req.user._id);
      if (!oid) return res.status(400).json({ message: 'Invalid user id' });
      await paymentsCol.insertOne({
        email: req.user.email,
        transactionId: req.body.transactionId || 'txn_' + Date.now(),
        amount: 5,
        date: new Date().toISOString().split('T')[0],
        status: 'success',
        createdAt: new Date(),
      });
      await usersCol.updateOne({ _id: oid }, { $set: { isPremium: true } });
      const user = await usersCol.findOne({ _id: oid }, { projection: { password: 0 } });
      const payload = { _id: user._id.toString(), name: user.name, email: user.email, photoURL: user.photoURL || '', role: user.role, isPremium: true };
      const token = signToken(payload);
      setTokenCookie(res, token);
      res.json({ message: 'Premium activated', token, user: payload });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // ══════════════════════════
  // CREATOR
  // ══════════════════════════
  app.get('/api/creator/stats', verifyToken, verifyCreatorOrAdmin, async (req, res) => {
    try {
      const agg = await promptsCol.aggregate([
        { $match: { creatorEmail: req.user.email } },
        { $group: { _id: null, totalCopies: { $sum: '$copyCount' }, totalBookmarks: { $sum: '$bookmarkCount' }, totalPrompts: { $sum: 1 } } },
      ]).toArray();
      res.json({ stats: agg[0] ? { totalCopies: agg[0].totalCopies, totalBookmarks: agg[0].totalBookmarks, totalPrompts: agg[0].totalPrompts } : { totalCopies: 0, totalBookmarks: 0, totalPrompts: 0 } });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  // ══════════════════════════
  // ADMIN
  // ══════════════════════════
  app.get('/api/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const [users, prompts, reviews, copies] = await Promise.all([
        usersCol.countDocuments(), promptsCol.countDocuments(), reviewsCol.countDocuments(),
        promptsCol.aggregate([{ $group: { _id: null, total: { $sum: '$copyCount' } } }]).toArray(),
      ]);
      res.json({ stats: { users, prompts, reviews, copies: copies[0]?.total || 0 } });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try { res.json(await usersCol.find({}, { projection: { password: 0 } }).toArray()); }
    catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.patch('/api/admin/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      await usersCol.updateOne({ _id: oid }, { $set: { role: req.body.role } });
      res.json({ message: 'Role updated' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.delete('/api/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      await usersCol.deleteOne({ _id: oid });
      res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.get('/api/admin/prompts', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const { page = 1, limit = 20 } = req.query;
      const prompts = await promptsCol.find({}).sort({ createdAt: -1 }).skip((parseInt(page) - 1) * parseInt(limit)).limit(parseInt(limit)).toArray();
      res.json(prompts);
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.patch('/api/admin/prompts/:id/status', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      const { status, rejectionFeedback } = req.body;
      await promptsCol.updateOne({ _id: oid }, { $set: { status, ...(rejectionFeedback && { rejectionFeedback }) } });
      res.json({ message: `Prompt ${status}` });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.patch('/api/admin/prompts/:id/feature', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      const p = await promptsCol.findOne({ _id: oid });
      await promptsCol.updateOne({ _id: oid }, { $set: { featured: !p?.featured } });
      res.json({ featured: !p?.featured });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.delete('/api/admin/prompts/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      await promptsCol.deleteOne({ _id: oid });
      res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.get('/api/admin/payments', verifyToken, verifyAdmin, async (req, res) => {
    try { res.json(await paymentsCol.find({}).sort({ createdAt: -1 }).toArray()); }
    catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.get('/api/admin/reports', verifyToken, verifyAdmin, async (req, res) => {
    try { res.json(await reportsCol.find({ resolved: { $ne: true } }).sort({ createdAt: -1 }).toArray()); }
    catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.patch('/api/admin/reports/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
      const oid = toObjectId(req.params.id);
      if (!oid) return res.status(400).json({ message: 'Invalid id' });
      const report = await reportsCol.findOne({ _id: oid });
      if (req.body.action === 'remove' && report?.promptId) {
        const promptOid = toObjectId(report.promptId);
        if (promptOid) await promptsCol.deleteOne({ _id: promptOid });
      }
      await reportsCol.updateOne({ _id: oid }, { $set: { resolved: true, action: req.body.action } });
      res.json({ message: 'Action taken' });
    } catch (err) { res.status(500).json({ message: err.message }); }
  });

  app.get('/', (req, res) => res.json({ status: '✅ PromptHive server running' }));
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
}

run().catch(console.error);
