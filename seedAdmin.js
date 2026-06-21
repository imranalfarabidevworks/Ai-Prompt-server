require('dotenv').config();
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

async function seed() {
  const client = new MongoClient(process.env.MONGODB_URI);
  await client.connect();
  const db = client.db('prompthive');
  const users = db.collection('users');

  const adminEmail = process.env.ADMIN_EMAIL || 'admin@prompthive.com';
  const adminPass  = process.env.ADMIN_PASS  || 'Admin@12345';

  const exists = await users.findOne({ email: adminEmail });
  if (exists) {
    // update role to admin in case
    await users.updateOne({ email: adminEmail }, { $set: { role: 'admin' } });
    console.log('✅ Admin already exists — role confirmed');
  } else {
    const hashed = await bcrypt.hash(adminPass, 10);
    await users.insertOne({
      name: 'Admin',
      email: adminEmail,
      password: hashed,
      photoURL: '',
      role: 'admin',
      isPremium: true,
      createdAt: new Date(),
    });
    console.log('✅ Admin created:', adminEmail);
  }
  await client.close();
}

seed().catch(console.error);
