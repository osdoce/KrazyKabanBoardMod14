import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  id: string;
  username: string;
  email: string;
}

declare module 'express' {
  interface Request {
    user?: JwtPayload;
  }
}

const SECRET_KEY = process.env.JWT_SECRET || 'default_secret_key';

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // Extraer el token del header Authorization
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1]; // "Bearer token"

  if (!token) {
    return res.status(401).json({ message: 'Acceso denegado: No hay token' });
  }

  // Verificar el token
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token no válido' });
    }

    // Adjuntar los datos del usuario al request
    req.user = decoded as JwtPayload;
    next();
  });
};
