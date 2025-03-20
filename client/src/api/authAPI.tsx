import { UserLogin } from "../interfaces/UserLogin";

const login = async (userInfo: UserLogin) => {
  // TODO: make a POST request to the login route
  const response = await fetch("/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json", // Specify that the request body is JSON
    },
    body: JSON.stringify(userInfo), // Convert the userInfo object to a JSON string
  });

  // Extract the user data from the server's response
  const user = await response.json();

  // Log the received user data to the console
  console.log("User: ", user);

  // Return the user data to the calling function
  return user;
};

export { login };
