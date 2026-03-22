const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Initialize Supabase
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);
// Add this at the very top after the imports
const path = require('path');

// Update the static files line to work in production
app.use(express.static(path.join(__dirname, 'website')));

// Update the routes to handle frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'index.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'dashboard.html'));
});

app.get('/checkout.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'checkout.html'));
});

app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'admin.html'));
});

// Add catch-all route for any other HTML files
app.get('*.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', req.path));
});
// Middleware
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('website'));

// ==================== AUTH MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Access denied. Please login.' });
    }
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(403).json({ error: 'Invalid or expired token' });
    }
};

// ==================== AUTH ROUTES ====================
// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields required' });
        }
        
        // Check if user exists
        const { data: existing } = await supabase
            .from('users')
            .select('email')
            .eq('email', email)
            .single();
        
        if (existing) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const { data: user, error } = await supabase
            .from('users')
            .insert([{
                name,
                email,
                password: hashedPassword,
                phone: phone || null,
                role: 'user'
            }])
            .select()
            .single();
        
        if (error) throw error;
        
        res.json({ 
            success: true, 
            message: 'Registration successful', 
            user: { id: user.id, name: user.name, email: user.email } 
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();
        
        if (error || !user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        
        res.json({ 
            success: true, 
            message: 'Login successful', 
            user: { id: user.id, name: user.name, email: user.email, role: user.role } 
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logout successful' });
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, name, email, phone, address, role, created_at')
            .eq('id', req.user.id)
            .single();
        
        if (error) throw error;
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { name, email, phone, address } = req.body;
        const updates = {};
        if (name) updates.name = name;
        if (email) updates.email = email;
        if (phone) updates.phone = phone;
        if (address) updates.address = address;
        
        const { data, error } = await supabase
            .from('users')
            .update(updates)
            .eq('id', req.user.id)
            .select()
            .single();
        
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== USER DASHBOARD ROUTES ====================
// Get user orders
app.get('/api/user/orders', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('orders')
            .select(`
                *,
                cars (*)
            `)
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add to wishlist
app.post('/api/user/wishlist/:carId', authenticateToken, async (req, res) => {
    try {
        const { data: existing } = await supabase
            .from('wishlist')
            .select('*')
            .eq('user_id', req.user.id)
            .eq('car_id', req.params.carId)
            .single();
        
        if (existing) {
            return res.status(400).json({ error: 'Car already in wishlist' });
        }
        
        const { data, error } = await supabase
            .from('wishlist')
            .insert([{
                user_id: req.user.id,
                car_id: parseInt(req.params.carId)
            }])
            .select();
        
        if (error) throw error;
        res.json({ success: true, message: 'Added to wishlist' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get wishlist
app.get('/api/user/wishlist', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('wishlist')
            .select(`
                *,
                cars (*)
            `)
            .eq('user_id', req.user.id);
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Remove from wishlist
app.delete('/api/user/wishlist/:carId', authenticateToken, async (req, res) => {
    try {
        const { error } = await supabase
            .from('wishlist')
            .delete()
            .eq('user_id', req.user.id)
            .eq('car_id', parseInt(req.params.carId));
        
        if (error) throw error;
        res.json({ success: true, message: 'Removed from wishlist' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create order (for logged in users)
app.post('/api/user/orders', authenticateToken, async (req, res) => {
    try {
        const { car_id, total_amount, payment_method } = req.body;
        
        if (!car_id || !total_amount) {
            return res.status(400).json({ error: 'Car ID and total amount are required' });
        }
        
        // Check if car exists and is available
        const { data: car, error: carError } = await supabase
            .from('cars')
            .select('status')
            .eq('id', car_id)
            .single();
        
        if (carError || !car) {
            return res.status(404).json({ error: 'Car not found' });
        }
        
        if (car.status !== 'available') {
            return res.status(400).json({ error: 'Car is not available' });
        }
        
        const { data, error } = await supabase
            .from('orders')
            .insert([{
                user_id: req.user.id,
                car_id: parseInt(car_id),
                total_amount: parseFloat(total_amount),
                payment_method: payment_method || 'credit_card',
                status: 'pending'
            }])
            .select();
        
        if (error) throw error;
        
        // Update car status
        await supabase
            .from('cars')
            .update({ status: 'reserved' })
            .eq('id', car_id);
        
        res.json({ success: true, message: 'Order created', order: data[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== GUEST CHECKOUT ROUTE ====================
// Guest checkout (no authentication required)
app.post('/api/guest/orders', async (req, res) => {
    try {
        const { car_id, total_amount, payment_method, customer_name, customer_email, customer_phone, customer_address } = req.body;
        
        if (!car_id || !total_amount) {
            return res.status(400).json({ error: 'Car ID and total amount are required' });
        }
        
        // Check if car exists and is available
        const { data: car, error: carError } = await supabase
            .from('cars')
            .select('status')
            .eq('id', car_id)
            .single();
        
        if (carError || !car) {
            return res.status(404).json({ error: 'Car not found' });
        }
        
        if (car.status !== 'available') {
            return res.status(400).json({ error: 'Car is not available' });
        }
        
        // Create order with guest info
        const { data, error } = await supabase
            .from('orders')
            .insert([{
                car_id: parseInt(car_id),
                total_amount: parseFloat(total_amount),
                payment_method: payment_method || 'credit_card',
                status: 'pending',
                customer_name: customer_name,
                customer_email: customer_email,
                customer_phone: customer_phone,
                customer_address: customer_address
            }])
            .select();
        
        if (error) throw error;
        
        // Update car status to reserved
        await supabase
            .from('cars')
            .update({ status: 'reserved' })
            .eq('id', car_id);
        
        res.json({ success: true, message: 'Order placed successfully!', order: data[0] });
    } catch (error) {
        console.error('Guest order error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== ADMIN ROUTES ====================
// Get all orders (admin only)
app.get('/api/admin/orders', authenticateToken, async (req, res) => {
    try {
        const { data: user } = await supabase
            .from('users')
            .select('role')
            .eq('id', req.user.id)
            .single();
        
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { data, error } = await supabase
            .from('orders')
            .select(`
                *,
                users (id, name, email),
                cars (*)
            `)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        const { data: user } = await supabase
            .from('users')
            .select('role')
            .eq('id', req.user.id)
            .single();
        
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { data, error } = await supabase
            .from('users')
            .select('id, name, email, phone, role, created_at')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update order status (admin only)
app.put('/api/admin/orders/:id', authenticateToken, async (req, res) => {
    try {
        const { data: user } = await supabase
            .from('users')
            .select('role')
            .eq('id', req.user.id)
            .single();
        
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        const { status } = req.body;
        const { data, error } = await supabase
            .from('orders')
            .update({ status })
            .eq('id', parseInt(req.params.id))
            .select();
        
        if (error) throw error;
        res.json(data[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== PUBLIC CAR ROUTES ====================
// Get all cars
app.get('/api/cars', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cars')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        res.json(data || []);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single car
app.get('/api/cars/:id', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cars')
            .select('*')
            .eq('id', parseInt(req.params.id))
            .single();
        
        if (error) throw error;
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SERVE FRONTEND ====================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'index.html'));
});

app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'dashboard.html'));
});

app.get('/checkout.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'checkout.html'));
});

app.get('/user-dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'user-dashboard.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log(`\n🚀 Server is running!`);
    console.log(`📍 http://localhost:${PORT}`);
    console.log(`📦 API: http://localhost:${PORT}/api/cars`);
    console.log(`👤 Dashboard: http://localhost:${PORT}/dashboard.html`);
    console.log(`🛒 Checkout: http://localhost:${PORT}/checkout.html`);
    console.log(`\n✨ Ready to go!\n`);
});

// Add this at the VERY TOP of server.js
console.log('Starting server...');

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
    process.exit(1);
});