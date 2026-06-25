require('dotenv').config();
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const dns = require('node:dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
async function seed() {
  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  console.log('✅ Connected to MongoDB');

  const db = client.db('prompthive');
  const users = db.collection('users');

  const demos = [
    {
      name: 'Admin',
      email: process.env.ADMIN_EMAIL || 'admin@prompthive.com',
      password: process.env.ADMIN_PASS || 'Admin@12345',
      role: 'admin',
      isPremium: true,
      photoURL: '',
    },
    {
      name: 'Creator',
      email: 'creator@prompthive.com',
      password: 'Creator@12345',
      role: 'creator',
      isPremium: true,
      photoURL: '',
    },
    {
      name: 'User',
      email: 'user@prompthive.com',
      password: 'User@12345',
      role: 'user',
      isPremium: false,
      photoURL: '',
    },
  ];

  for (const demo of demos) {
    const hashed = await bcrypt.hash(demo.password, 10);
    const exists = await users.findOne({ email: demo.email });

    if (exists) {
      await users.updateOne(
        { email: demo.email },
        { $set: { role: demo.role, isPremium: demo.isPremium, password: hashed } }
      );
      console.log(`✅ Updated: ${demo.email} → role: ${demo.role}`);
    } else {
      await users.insertOne({
        ...demo,
        password: hashed,
        bookmarks: [],
        promptCount: 0,
        createdAt: new Date(),
      });
      console.log(`✅ Created: ${demo.email} → role: ${demo.role}`);
    }
  }

  console.log('\n🎉 Done! 3 demo accounts ready.');
  await client.close();
}

seed().catch(console.error);
