import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const login = async (req: Request, res: Response) => {
  // TODO: If the user exists and the password is correct, return a JWT token

  // Extract username and password from the request body
  const { username, password } = req.body;

  // Find the user by username from the database
  const user = await User.findOne({
    where: { username },
  });

  // Check if the user was found
  if (!user) {
    // Respond with a 404 Not Found status and an error message
    return res.status(404).json({ message: 'User not found!' });
  }

  // Compare the provided password with the hashed password in the database
    const validPassword = await bcrypt.compare(password, user.password);

  // Check if the password is valid
  if (!validPassword) {
    // Respond with a 400 Bad Request status and an error message
    return res.status(400).json({ message: 'Incorrect Password!'});
  }

  // Get the secret key from environment variables
    const secretKey = process.env.JWT_SECRET_KEY || '';

  // Create a JWT token with the user's username as payload and set expiry to 1 hour
  const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });

  // Respond with the generated JWT token
  return res.json({ token });
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
