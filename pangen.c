#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

int
main (int argc, char *argv[])
{
	unsigned long int	i = 0,				// Increment for card numbers
				b = 0,				// Increment for buffer contents
			 	startnum = 0,			// Starting card number
				count = 0,			// Number of card numbers to find
				found = 0;			// Counf of numbers found

	unsigned char		number[16],			// String containing card number
				hash[40];			// String containing hex hash

	unsigned char		buffer[SHA_DIGEST_LENGTH],	// Buffer for binary hash data
				*digest;			// Buffer for HMAC data

	size_t			length;				// Contains length of string

	// Check command line arguments and set initial parameters
	switch (argc)
	{
		case 1:						// Only command and no arguments
			fprintf (stderr, "Too few arguments\n");
			fprintf (stderr, "Usage: %s \033[4mCOUNT\033[0m [START NUMBER]\n!",argv[0]);
			exit (0);
		case 2:						// Command and count only
			count = atol (argv[1]);
			if (count > 2147483647)			// Count exceeds maximum size for long int
			{
				fprintf (stderr, "COUNT too large\n");
				exit (0);
			}
			startnum = 0;
			break;
		case 3:						// Command, count and starting number
			count = atol (argv[1]);
			if (strlen (argv[2]) > 16)
			{
				fprintf (stderr, "START NUMBER longer than 16 digits\n");
				fprintf (stderr, "Usage: %s \033[4mCOUNT\033[0m [START NUMBER]\n!",argv[0]);
				exit (0);
			}	
			startnum = atol (argv[2]);
			break;
		default:					// Too many arguments
			fprintf (stderr, "Too many arguments\n");
			fprintf (stderr, "Usage: %s \033[4mCOUNT\033[0m [START NUMBER]\n", argv[0]);
			return (0);
	}

	// Out in CSV format
	printf ("Cardnumber,Last_four_digits,SHA1,HMAC-SHA1\n");

	// Start searching for valid card numbers.
	// Terminate when 'count' numbers are found or when largest number reached.
	for (i = startnum; i <= 9999999999999999; i++)
	{
		// Copy number to a string for Luhn checking
		sprintf (number, "%016ld", i);
		length = sizeof(number);

		// Check if it passes the Luhn check and print the results
		if (isValidNumber(number) != 0)
		{
			// Until we've found the amount of numbers we want
			if (found++ < count)
			{
				// Print the full card number
				printf("%s,", number);

				// Print the last four digits
				printf("%s,", &number[12]);

				// Calculate SHA1 hash and store in buffer
				SHA1 (number, length, buffer);

				// Convert buffer contents to hex string
				for (b = 0; b < SHA_DIGEST_LENGTH; b++)
				{
					printf ("%02x", buffer[b]);
				}
				printf (",");

				// Calculate HMAC and store in buffer
				digest = HMAC (EVP_sha1(), &number[12], 4, number, length, NULL, NULL);

				// Print the HMAC hash
				for (b = 0; b < SHA_DIGEST_LENGTH; b++)
				{
					printf("%02x",digest[b]);
				}
				printf ("\n");
			}
			else exit (0);	// Terminate if found matches count
		}
	}
}


// Function to perform Luhn check on number string
int
isValidNumber (const char *number)
{
	int n = 16, i, alternate, sum;

	if (!number) return 0;				// Return of number string is invalid

	for (alternate = 0, sum = 0, i = n - 1; i > -1; --i)
	{
		if (!isdigit(number[i])) return 0;	// Return if digit is not numeric

		n = number[i] - '0';			// Convert character to digit to integer

		if (alternate)				// Are we on an alternate digit?
		{
			n *= 2;				// Double alternate digits
			if (n > 9) n = (n % 10) + 1;	// Convert two digit numbers to single digit
        	}
		alternate = !alternate;			// Swap alternate status
		sum += n;				// Keep a running total
	}
	return (sum % 10 == 0);				// Return 'true' if MOD10 is 0
}
