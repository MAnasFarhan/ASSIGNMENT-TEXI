// ASSIGNMENT-TEXI1
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const uri = 'mongodb+srv://Anas:KxGZ8SZBWykDuG1d@cluster0.7hfi53x.mongodb.net/';
const client = new MongoClient(uri);
let db;

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';
const saltRounds = 10;

const path = require('path');

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname)));

function authenticate(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

function authorize(roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
}

async function start() {
    try {
        await client.connect();
        db = client.db('MyTaxi');
        console.log("Connected to MongoDB");
        app.listen(3000, () => console.log("Server running on http://localhost:3000"));
    } catch (err) {
        console.error(err);
    }
}

start();

// ---------------- AUTH ----------------
app.post('/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!['passenger', 'driver', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }

    try {
        const existing = await db.collection('users').findOne({ email });
        if (existing) return res.status(409).json({ error: 'Email already registered' });

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const result = await db.collection('users').insertOne({ name, email, password: hashedPassword, role });
        res.status(201).json({ message: 'User registered successfully', id: result.insertedId });
    } catch {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await db.collection('users').findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user._id.toString(), role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );
        res.status(200).json({ token });
    } catch {
        res.status(500).json({ error: 'Login failed' });
    }
});

// ---------------- PASSENGER ----------------
app.post('/passengers/order', authenticate, authorize(['passenger']), async (req, res) => {
    try {
        const order = { ...req.body, userId: req.user.id.toString(), status: 'pending' };
        const result = await db.collection('orders').insertOne(order);
        res.status(201).json({ id: result.insertedId });
    } catch (err) {
        console.error(err); // Log to console
        res.status(400).json({ error: 'Failed to create order', details: err.message });
    }

});

app.get('/passengers/orders', authenticate, authorize(['passenger']), async (req, res) => {
    try {
        const userId = typeof req.user.id === 'string' ? new ObjectId(req.user.id) : req.user.id;
        const orders = await db.collection('orders').find({ userId: req.user.id }).toArray();
        res.status(200).json(orders);
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Failed to retrieve orders', details: err.message });
    }
});


app.delete('/passengers/order/:id', authenticate, authorize(['passenger']), async (req, res) => {
    const { id } = req.params;
    try {
        const result = await db.collection('orders').deleteOne({ _id: new ObjectId(id), userId: req.user.id, status: 'pending' });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Order not found or not cancelable' });
        res.status(200).json({ message: 'Order cancelled successfully' });
    } catch (err) {
        console.error(err); // Log to console
        res.status(400).json({ error: 'Failed to cancel order', details: err.message });
    }
});

app.delete('/passengers/account', authenticate, authorize(['passenger']), async (req, res) => {
    try {
        await db.collection('users').deleteOne({ _id: new ObjectId(req.user.id) });
        res.status(200).json({ message: 'Account successfully deleted' });
    } catch (err) {
        console.error(err); // Log to console
        res.status(400).json({ error: 'Failed to delete account', details: err.message });
    }
});

app.get('/passengers/order/:id/driver', authenticate, authorize(['passenger']), async (req, res) => {
    try {
        const order = await db.collection('orders').findOne({
            _id: new ObjectId(req.params.id),
            userId: req.user.id
        });

        if (!order || order.status !== 'accepted' || !order.driverId) {
            return res.status(404).json({ error: 'No driver assigned' });
        }

        const driver = await db.collection('users').findOne(
            { _id: order.driverId },
            {
                projection: {
                    name: 1,
                    phone: 1,
                    carname: 1,
                    locationFrom: 1,
                    arrivingInMinutes: 1,
                
                }
            }
        );

        if (!driver) {
            return res.status(404).json({ error: 'Driver not found' });
        }

        res.status(200).json(driver);
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Failed to retrieve driver info', details: err.message });
    }
});

app.get('/drivers/orders', authenticate, authorize(['driver']), async (req, res) => {
    try {
        const orders = await db.collection('orders').find({ status: 'pending' }).toArray();
        res.status(200).json(orders);
    } catch (err) {
        console.error(err); // Log to console
        res.status(400).json({ error: 'Failed to retrieve orders', details: err.message });
    }
});

app.post('/passengers/order/:id/complete', authenticate, authorize(['passenger']), async (req, res) => {
    try {
        const result = await db.collection('orders').updateOne(
            {
                _id: new ObjectId(req.params.id),
                userId: req.user.id,
                status: 'accepted'
            },
            { $set: { status: 'completed' } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'Order not found or not eligible to complete' });
        }

        res.status(200).json({ message: 'Order marked as completed' });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Failed to complete order', details: err.message });
    }
});

// ---------------- DRIVER ----------------
app.get('/drivers/orders', authenticate, authorize(['driver']), async (req, res) => {
    try {
        const orders = await db.collection('orders').find({ status: 'pending' }).toArray();
        res.status(200).json(orders);
    } catch {
        res.status(400).json({ error: 'Failed to retrieve orders' });
    }
});

app.post('/drivers/accept', authenticate, authorize(['driver']), async (req, res) => {
    const { orderId } = req.body;
    try {
        const result = await db.collection('orders').updateOne(
            { _id: new ObjectId(orderId), status: 'pending' },
            { $set: { status: 'accepted', driverId: new ObjectId(req.user.id) } }
        );
        if (result.modifiedCount === 0) return res.status(404).json({ error: 'Order not found or already accepted' });
        res.json({ message: 'Order accepted' });
    } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Failed to accept order', details: err.message });
}
});

app.post('/drivers/order/:id/cancel', authenticate, authorize(['driver']), async (req, res) => {
    try {
        const result = await db.collection('orders').updateOne(
            {
                _id: new ObjectId(req.params.id),
                driverId: new ObjectId(req.user.id),
                status: 'accepted'
            },
            { $set: { status: 'pending' }, $unset: { driverId: "" } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'Order not found or not cancelable by this driver' });
        }

        res.status(200).json({ message: 'Order canceled, now available for others' });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Failed to cancel order', details: err.message });
    }
});

app.put('/drivers/profile', authenticate, authorize(['driver']), async (req, res) => {
    const { name, email, password, phone, carname, locationFrom, arrivingInMinutes } = req.body;

    try {
        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.user.id) },
            { $set: { name, email, password, phone, carname, locationFrom, arrivingInMinutes } }
        );

        if (result.modifiedCount === 0)
            return res.status(404).json({ error: 'Driver not found' });

        res.json({ message: 'Profile updated' });
    } catch (err) {
        res.status(400).json({ error: 'Failed to update profile', details: err.message });
    }
});

app.delete('/drivers/account', authenticate, authorize(['driver']), async (req, res) => {
    try {
        const userId = typeof req.user.id === 'string' ? new ObjectId(req.user.id) : req.user.id;

        const result = await db.collection('users').deleteOne({ _id: userId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Account not found' });
        }

        res.status(200).json({ message: 'Account successfully deleted' });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Failed to delete account', details: err.message });
    }
});

app.get('/drivers/my-orders', authenticate, authorize(['driver']), async (req, res) => {
    try {
        const driverId = new ObjectId(req.user.id);

        const orders = await db.collection('orders').find({
            driverId: driverId,
            status: 'accepted'
        }).toArray();

        res.status(200).json(orders);
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Failed to retrieve driver orders', details: err.message });
    }
});

// ---------------- ADMIN ----------------
app.get('/admin/users', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const users = await db.collection('users').find({}, { projection: { password: 0 } }).toArray();
        res.status(200).json(users);
    } catch {
        res.status(500).json({ error: 'Failed to fetch user accounts' });
    }
});

app.delete('/admin/users/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        await db.collection('users').deleteOne({ _id: ObjectId(req.params.id) });
        res.status(204).send();
    } catch {
        res.status(400).json({ error: 'Failed to delete user' });
    }
});

app.get('/admin/orders', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const orders = await db.collection('orders').find().toArray();
        res.json(orders);
    } catch {
        res.status(400).json({ error: 'Failed to retrieve orders' });
    }
});


