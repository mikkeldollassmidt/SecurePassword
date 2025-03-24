using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;

namespace SecurePassword
{

    /// <summary>
    /// Jeg har forresten undværret at lave det i MVC
    /// Jeg ville bare pointere at jeg havde fattet det ;)
    /// Håber der er nok kommentare
    /// </summary>
    class Program
    {

        // Connection String
        const string ConnString = "Server=localhost;Database=SecurePasswords;User ID=root;Password=;";

        static void Main()
        {
            // MENU
            while (true)
            {
                Console.WriteLine("\n1. Opret konto\n2. Login\n3. Afslut");
                string choice = Console.ReadLine();
                if (choice == "1") RegisterUser();
                else if (choice == "2") LoginUser();
                else if (choice == "3") break;
            }
        }

        static void RegisterUser()
        {
            // Visuals
            Console.Write("Brugernavn: ");
            string username = Console.ReadLine();
            Console.Write("Adgangskode: ");
            string password = Console.ReadLine();

            // Establish a connection to the MySQL database using the provided connection string
            using (MySqlConnection conn = new MySqlConnection(ConnString))
            {
                conn.Open();

                // Checking if username already exists
                using (MySqlCommand checkCmd = new MySqlCommand("SELECT COUNT(*) FROM Logins WHERE username=@user", conn))
                {
                    // Add the username parameter to the SQL command to prevent SQL injection
                    checkCmd.Parameters.AddWithValue("@user", username);

                    // The ExecuteScalar() method returns the first column of the first row in the result set
                    int userExists = Convert.ToInt32(checkCmd.ExecuteScalar());

                    // Checck if userExists is more than 0 to see if the username already is in the database.
                    if (userExists > 0)
                    {
                        Console.WriteLine("❌ Brugernavnet findes allerede! Vælg et andet.");
                        return;
                    }
                }

                // Generates salt with GenrateSalt method
                byte[] salt = GenerateSalt();
                // Hashing password with HashPaddword method
                byte[] hash = HashPassword(password, salt);

                // Inserting into Logins table
                using (MySqlCommand cmd = new MySqlCommand("INSERT INTO Logins (username, hash, salt) VALUES (@user, @hash, @salt)", conn))
                {
                    // Add as parameters
                    cmd.Parameters.AddWithValue("@user", username);
                    cmd.Parameters.AddWithValue("@hash", Convert.ToBase64String(hash));
                    cmd.Parameters.AddWithValue("@salt", Convert.ToBase64String(salt));

                    // Execute the query
                    cmd.ExecuteNonQuery();
                }
            }

            Console.WriteLine("✅ Bruger oprettet!");
        }

        static void LoginUser()
        {
            while (true) // While true to loop infinity tries on user login.
            {
                // Visuals
                Console.Write("Brugernavn: ");
                string username = Console.ReadLine();
                Console.Write("Adgangskode: ");
                string password = Console.ReadLine();

                // Initializing variables to store the hash and salt values.
                byte[] storedHash = null;
                byte[] storedSalt = null;

                // Establish a connection to the MySQL database using the provided connection string
                using (MySqlConnection conn = new MySqlConnection(ConnString))
                {
                    conn.Open();
                    using (MySqlCommand cmd = new MySqlCommand("SELECT hash, salt FROM Logins WHERE username=@user", conn))
                    {
                        // Add the username parameter to the SQL command to prevent SQL injection
                        cmd.Parameters.AddWithValue("@user", username);

                        //Executing
                        using (MySqlDataReader reader = cmd.ExecuteReader())
                        {
                            // If no data found on user, display error.
                            if (!reader.Read())
                            {
                                Console.WriteLine("❌ Ugyldige loginoplysninger! Prøv igen.");
                                continue; // Restarting the loop
                            }

                            // Retrieve and decode the stored hash and salt from the database
                            storedHash = Convert.FromBase64String(reader.GetString(0));
                            storedSalt = Convert.FromBase64String(reader.GetString(1));
                        }
                    }
                }

                if (storedHash != null && storedSalt != null && storedHash.SequenceEqual(HashPassword(password, storedSalt)))
                {
                    Console.WriteLine("✅ Login succesfuldt!");
                    break; // Cancels loop, wheb login is successfull
                }
                else
                {
                    Console.WriteLine("❌ Ugyldige loginoplysninger! Prøv igen.");
                }
            }
        }

        // Generates a cryptographically secure salt of 16 bytes using RNGCryptoServiceProvider
        static byte[] GenerateSalt()
        {
            // Create a byte aray of 16 byte for the salt
            byte[] salt = new byte[16];

            // Random bytes
            new RNGCryptoServiceProvider().GetBytes(salt);

            return salt;
        }

        // Hashes the password using the specifed salt and the PBKDF2 algorithm
        static byte[] HashPassword(string password, byte[] salt)
        {
            // Returns a 32-byte hash of the password
            return new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256).GetBytes(32);
        }
    }
}
