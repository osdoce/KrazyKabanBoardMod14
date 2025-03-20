import { JwtPayload, jwtDecode } from 'jwt-decode';

class AuthService {
  getProfile() {
    // TODO: return the decoded token
    
    // Get the token from the current object or class
    const token = this.getToken(); 
    // Decode the JWT token using the jwtDecode function
    // and type the decoded data as JwtPayload
    const decoded: JwtPayload = jwtDecode(token); 
    // Return the decoded data 
    return decoded;
  }

  loggedIn() {
    // TODO: return a value that indicates if the user is logged in
    // Get the token from the current object or class
    const token = this.getToken();
    // Check if the retrieved token is explicitly 'undefined'
    if (token === 'undefined') {
    // Remove the token from local storage if it's 'undefined'
    localStorage.removeItem('token'); 
    } 
    // Check if the token exists and has a truthy value
    else if (token) {
      // Check if the token has expired
      const isExpired = this.isTokenExpired(token); 
      // Return true if the token exists and is not expired
      return token && !isExpired; 
    } 
    // If the token is not found or is not truthy, return false
    else {
      return false;
    }
  }
  
  isTokenExpired(token: string) {
    // TODO: return a value that indicates if the token is expired
    if (token) {
      const data = jwtDecode<JwtPayload>(token);
      const curTime = Date.now() / 1000; //current time in seconds
      return data?.exp && data.exp < curTime;  //returns true if data.exp is less than the curTime and false for the vice versa
    } else {
      return true;
    }
  }

  getToken(): string {
    // TODO: return the token
    // Get the token from local storage
    const token = localStorage.getItem('token'); 
    // Check if a token exists in local storage
    if (token) {
      // If a token exists, return it
      return token;
    } else {
      // If no token exists, return an empty string
      return ""; 
    }
  }

  login(idToken: string) {
    // TODO: set the token to localStorage
    // Store the idToken in local storage with the key 'token'
    localStorage.setItem('token', idToken); 
    // TODO: redirect to the home page
    window.location.assign('/') ;
  }

  logout() {
    // TODO: remove the token from localStorage
    // Remove the item with the key 'token' from local storage
    localStorage.removeItem('token');
    // TODO: redirect to the login page
    window.location.assign('/');
}
  }

export default new AuthService();
