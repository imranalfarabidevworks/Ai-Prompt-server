// Run this once: node seed.js
// Creates demo admin, creator, user accounts
require('dotenv').config();
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

const uri = process.env.MONGODB_URI;

async function seed() {
  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db('prompthive');
  const users = db.collection('users');

  const demos = [
    { name: 'Admin',   email: 'admin@prompthive.com',   password: 'Admin@12345',   role: 'admin',   isPremium: true },
    { name: 'Creator', email: 'creator@prompthive.com', password: 'Creator@12345', role: 'creator', isPremium: true },
    { name: 'User',    email: 'user@prompthive.com',    password: 'User@12345',    role: 'user',    isPremium: false },
  ];

  for (const demo of demos) {
    const exists = await users.findOne({ email: demo.email });
    if (exists) {
      // Update role if exists
      await users.updateOne({ email: demo.email }, { $set: { role: demo.role, isPremium: demo.isPremium } });
      console.log(`✅ Updated: ${demo.email} → role: ${demo.role}`);
    } else {
      const hashed = await bcrypt.hash(demo.password, 10);
      await users.insertOne({ ...demo, password: hashed, photoURL: '', bookmarks: [], promptCount: 0, createdAt: new Date() });
      console.log(`✅ Created: ${demo.email} → role: ${demo.role}`);
    }
  }

  console.log('\n🎉 Seed complete! Demo accounts ready.');
  await client.close();
}

seed().catch(console.error);
