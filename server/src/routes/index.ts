import { Router } from 'express';
import authRoutes from './auth-routes.js';
import apiRoutes from './api/index.js';
import { authenticateToken } from '../middleware/auth.js';

const router = Router();

router.use('/auth', authRoutes);
// TODO: Add authentication to the API routes
// Define a middleware to authenticate incoming requests
router.use('/api', authenticateToken, apiRoutes); 


export default router;
