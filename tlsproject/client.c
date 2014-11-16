
/*
 * sig_client.c
 *
 * Author: Alec Guertin
 * University of California, Berkeley
 * CS 161 - Computer Security
 * Fall 2014 Semester
 * Project 1
 */

#include "client.h"

/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();

unsigned long long assign_to_long(unsigned char* val_array);

int main(int argc, char **argv) {
	int err, option_index, c, clientlen, counter;
	unsigned char rcv_plaintext[AES_BLOCK_SIZE];
	unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
	unsigned char send_plaintext[AES_BLOCK_SIZE];
	unsigned char send_ciphertext[AES_BLOCK_SIZE];
	aes_context enc_ctx, dec_ctx;
	in_addr_t ip_addr;
	struct sockaddr_in server_addr;
	FILE *c_file, *d_file, *m_file;
	ssize_t read_size, write_size;
	struct sockaddr_in client_addr;
	tls_msg err_msg, send_msg, rcv_msg;
	mpz_t client_exp, client_mod;
	fd_set readfds;
	struct timeval tv;

	c_file = d_file = m_file = NULL;

	mpz_init(client_exp);
	mpz_init(client_mod);


	/*
	 * This section is networking code that you don't need to worry about.
	 * Look further down in the function for your part.
	 */

	memset(&ip_addr, 0, sizeof(in_addr_t));

	option_index = 0;
	err = 0;

	static struct option long_options[] = {
		{"ip", required_argument, 0, 'i'},
		{"cert", required_argument, 0, 'c'},
		{"exponent", required_argument, 0, 'd'},
		{"modulus", required_argument, 0, 'm'},
		{0, 0, 0, 0},
	};

	while (1) {
		c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
		if (c < 0) {
			break;
		}
		switch(c) {
		case 0:
			usage();
			break;
		case 'c':
			c_file = fopen(optarg, "r");
			if (c_file == NULL) {
				perror("Certificate file error");
				exit(1);
			}
			break;
		case 'd':
			d_file = fopen(optarg, "r");
			if (d_file == NULL) {
				perror("Exponent file error");
				exit(1);
			}
			break;
		case 'i':
			ip_addr = inet_addr(optarg);
			break;
		case 'm':
			m_file = fopen(optarg, "r");
			if (m_file == NULL) {
				perror("Modulus file error");
				exit(1);
			}
			break;
		case '?':
			usage();
			break;
		default:
			usage();
			break;
		}
	}

	if (d_file == NULL || c_file == NULL || m_file == NULL) {
		usage();
	}
	if (argc != 9) {
		usage();
	}

	mpz_inp_str(client_exp, d_file, 0);
	mpz_inp_str(client_mod, m_file, 0);

	signal(SIGTERM, kill_handler);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("Could not open socket");
		exit(1);
	}


	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = ip_addr;
	server_addr.sin_port = htons(HANDSHAKE_PORT);
	err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (err < 0) {
		perror("Could not bind socket");
		cleanup();
	}

	// YOUR CODE HERE
	// IMPLEMENT THE TLS HANDSHAKE
	int send_message_int, receive_messge_int;
	/* error handling (To be continued) */
	// ********************************************************************
	// ********************************************************************
	// ********************************************************************
	
	// Whenever send or receive, need to check this feedback
	int feedback;

	//  =============== [Send] Client Hello =======================
	hello_message client_hello_message;
	int client_random;
	int server_random;
	memset(&client_hello_message, 0, sizeof(hello_message));

	client_random = random_int();
	client_hello_message.type = CLIENT_HELLO;
	client_hello_message.random = client_random;
	client_hello_message.cipher_suite = TLS_RSA_WITH_AES_128_ECB_SHA256;
	feedback = send_tls_message(sockfd, &client_hello_message, sizeof(hello_message));
	if (feedback != ERR_OK){
		perror("[CLIENT_HELLO]: can't send tls message");
		cleanup();	
	}

	//  =============== [Receive] Sever Hello =======================
	hello_message server_hello_message;
	memset(&server_hello_message, 0, sizeof(hello_message));
	feedback = receive_tls_message(sockfd, &server_hello_message, sizeof(hello_message), SERVER_HELLO);
	if (feedback != ERR_OK){
		perror("[SERVER_HELLO]: can't receive tls message");
		cleanup();		
	}
	server_random = server_hello_message.random;
	printf("server_random: %d\n", server_random);


	//  =============== [Send] Client Certificate ================
	mpz_t client_certificate_mpz;
	cert_message client_certificate;
	int byte_read;
	mpz_init(client_certificate_mpz);
	// May need to verify whether we connect to the correct server(i.e.torus.ce.berkeley.edu).
	memset(&client_certificate, 0, sizeof(cert_message));
	client_certificate.type = CLIENT_CERTIFICATE;
	fread(client_certificate.cert, RSA_MAX_LEN, 1, c_file);
	//printf("Client Certificate: %s\n", client_certificate.cert);
	feedback = send_tls_message(sockfd, &client_certificate, CERT_MSG_SIZE);
	if (feedback != ERR_OK){
		perror("[CLIENT CERTIFICATE]: can't send tls message");
		cleanup();
	}

	//  =============== [Receive] Server Certificate ================
	cert_message server_certificate;
	mpz_t decrypted_sever_cert_mpz;
	mpz_t ca_exponent;
	mpz_t ca_modulus;
	mpz_t server_public_key_exponent;
	mpz_t server_public_key_modulus;
	char decrypted_server_cert [RSA_MAX_LEN];

	memset(&server_certificate, 0, sizeof(cert_message));
	mpz_init(decrypted_sever_cert_mpz);
	mpz_init(ca_exponent);
	mpz_init(ca_modulus);
	mpz_init(server_public_key_exponent);
	mpz_init(server_public_key_modulus);
	memset(decrypted_server_cert, 0, RSA_MAX_LEN);

	feedback = receive_tls_message(sockfd, &server_certificate, sizeof(cert_message), SERVER_CERTIFICATE);
	if (feedback != ERR_OK){
		perror("[SERVER CERTIFICATE]: can't receive tls message");
		cleanup();
	}
	// May need to verify whether we connect to the correct server(i.e.torus.ce.berkeley.edu).
	// Decrypt Server Certificate
	mpz_set_str(ca_exponent, CA_EXPONENT, 0);
	mpz_set_str(ca_modulus, CA_MODULUS, 0);
	decrypt_cert(decrypted_sever_cert_mpz, &server_certificate, ca_exponent, ca_modulus);
	mpz_get_ascii(decrypted_server_cert, decrypted_sever_cert_mpz);                       // Convert mpz to char array
	//printf("decrypted_server_cert: %s\n", decrypted_server_cert);
	get_cert_exponent(server_public_key_exponent, decrypted_server_cert);
	get_cert_modulus(server_public_key_modulus, decrypted_server_cert);


	//  =============== [Send] E_server_public_key (Premaster Secret) ================
	// Construct encrypted(premaster secret)
	mpz_t premaster_secret_encrypted, premaster_secret_mpz;
	int premaster_secret;
	char premaster[16];
	ps_msg encrypted_ps_message;
	mpz_init(premaster_secret_encrypted);
	mpz_init(premaster_secret_mpz);	
	memset(&encrypted_ps_message, 0, sizeof(ps_msg));
	
	// Generate and Covert Premaster Secret to mpz
	premaster_secret = random_int();
	sprintf(premaster, "%d", premaster_secret);
	printf("premaster_secret: %d\n", premaster_secret);
	mpz_set_str(premaster_secret_mpz, premaster, 10);
	// perform_rsa(premaster_secret_encrypted, premaster_secret_mpz, server_public_key_exponent, server_public_key_modulus);
	// ps_msg *encrypted_ps_message;
	// encrypted_ps_message = (ps_msg*) malloc(sizeof(ps_msg));
	// encrypted_ps_message->type = PREMASTER_SECRET;
	// mpz_get_ascii(encrypted_ps_message->ps, premaster_secret_encrypted);
	// send_tls_message(sockfd, encrypted_ps_message, sizeof(ps_msg));
	// ps_msg encrypted_server_ms_message;
	// memset(&encrypted_server_ms_message, 0, sizeof(ps_msg));
	// receive_messge_int = receive_tls_message(sockfd, &encrypted_server_ms_message, sizeof(ps_msg), PREMASTER_SECRET);
	// if (receive_messge_int == ERR_FAILURE) {
	// 	perror("Could not get the master secret");
	// 	cleanup();
	// }
	// gmp_printf("premaster_secret_mpz: %Zd\n", premaster_secret_mpz);
	// gmp_printf("server_public_key_exponent: %Zx\n", server_public_key_exponent);
	// gmp_printf("server_public_key_modulus: %Zx\n", server_public_key_modulus);
	perform_rsa(premaster_secret_encrypted, premaster_secret_mpz, server_public_key_exponent, server_public_key_modulus);
	encrypted_ps_message.type = PREMASTER_SECRET;
	mpz_get_str(encrypted_ps_message.ps, 16, premaster_secret_encrypted);
	feedback = send_tls_message(sockfd, &encrypted_ps_message, sizeof(ps_msg));
	if (feedback != ERR_OK) {
		perror("[E_server_public_key (Premaster secret)]: can't send tls message");
		cleanup();
	}
	
	//  =============== [Receive] E_client_public_key (Master Secret) ================
	ps_msg encrypted_server_ms_message;
	mpz_t decrypted_ms, master_secret_test, master_secret_mpz;
	unsigned long long master_secret_long;

	unsigned char master_secret[SHA_BLOCK_SIZE];
	mpz_t master_secret_mpz;
	memset(&encrypted_server_ms_message, 0, sizeof(ps_msg));
	mpz_init(decrypted_ms);
	memset(master_secret, 0, SHA_BLOCK_SIZE);
	mpz_init(master_secret_mpz);
	feedback = receive_tls_message(sockfd, &encrypted_server_ms_message, sizeof(ps_msg), VERIFY_MASTER_SECRET);
	if (feedback != ERR_OK) {
		perror("[E_client_public_key (master secret)]: can't receive tls message");
		cleanup();
	}

	decrypt_verify_master_secret(decrypted_ms, &encrypted_server_ms_message, client_exp, client_mod);
	compute_master_secret(premaster_secret, client_random, server_random, master_secret);
	char* master_secret_str = hex_to_str(master_secret, SHA_BLOCK_SIZE);
	mpz_set_str(master_secret_mpz, master_secret_str, 16);
	gmp_printf("master_secret_mpz: %Zd\n", master_secret_mpz);
	gmp_printf("decrypted_ms: %Zd\n", decrypted_ms);
	int result = mpz_cmp(master_secret_mpz, decrypted_ms);

	if (result != 0) {
		perror("Decrypted server master secret doesn't match computed master secret!");
		cleanup();
	}

	printf("result: %d\n", result);
	free(master_secret_str);
	// ********************************************************************
	// ********************************************************************
	// ********************************************************************
	/*
	 * START ENCRYPTED MESSAGES
	 */

	memset(send_plaintext, 0, AES_BLOCK_SIZE);
	memset(send_ciphertext, 0, AES_BLOCK_SIZE);
	memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
	memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

	memset(&rcv_msg, 0, TLS_MSG_SIZE);

	aes_init(&enc_ctx);
	aes_init(&dec_ctx);
	
	// YOUR CODE HERE
	// SET AES KEYS
	aes_setkey_enc(&enc_ctx, master_secret, 128);
	aes_setkey_dec(&dec_ctx, master_secret, 128);

	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	/* Send and receive data. */
	while (1) {
		FD_ZERO(&readfds);
		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(sockfd, &readfds);
		tv.tv_sec = 2;
		tv.tv_usec = 10;

		select(sockfd+1, &readfds, NULL, NULL, &tv);
		//printf("Ready\n");
		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			counter = 0;
			memset(&send_msg, 0, TLS_MSG_SIZE);
			send_msg.type = ENCRYPTED_MESSAGE;
			memset(send_plaintext, 0, AES_BLOCK_SIZE);
			read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
			//printf("send_plaintext: %s\n", send_plaintext);
			while (read_size > 0 && (unsigned int) counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
				if (read_size > 0) {
					err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
					memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
					counter += AES_BLOCK_SIZE;
				}
				memset(send_plaintext, 0, AES_BLOCK_SIZE);
				read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
			}
			write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
			if (write_size < 0) {
				perror("Could not write to socket");
				cleanup();
			}
		} else if (FD_ISSET(sockfd, &readfds)) {
			memset(&rcv_msg, 0, TLS_MSG_SIZE);
			memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
			read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
			if (read_size > 0) {
				if (rcv_msg.type != ENCRYPTED_MESSAGE) {
					goto out;
				}
				memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
				counter = 0;
				while ((unsigned int) counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
					aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
					printf("%s", rcv_plaintext);
					counter += AES_BLOCK_SIZE;
					memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
				}
			}
		}

	}

out:
	close(sockfd);
	mpz_clear(client_exp);
	mpz_clear(client_mod);
	mpz_clear(client_certificate_mpz);
	mpz_clear(decrypted_sever_cert_mpz);
	mpz_clear(ca_exponent);
	mpz_clear(ca_modulus);
	mpz_clear(premaster_secret_encrypted);
	mpz_clear(server_public_key_exponent);
	mpz_clear(server_public_key_modulus);
	mpz_clear(premaster_secret_mpz);
	mpz_clear(decrypted_ms);
	mpz_clear(master_secret_mpz);
	mpz_clear(master_secret_test);
	return 0;
}

/*
 * \brief                  Decrypts the certificate in the message cert.
 *
 * \param decrypted_cert   This mpz_t stores the final value of the binary
 *                         for the decrypted certificate. Write the end
 *                         result here.
 * \param cert             The message containing the encrypted certificate.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the certificate.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the certificate.
 */
void
decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod)
{
	mpz_t certificate;
	mpz_init(certificate);
	mpz_set_str(certificate, cert->cert, 0);
	perform_rsa(decrypted_cert, certificate, key_exp, key_mod);
	mpz_clear(certificate);
}

/*
 * \brief                  Decrypts the master secret in the message ms_ver.
 *
 * \param decrypted_ms     This mpz_t stores the final value of the binary
 *                         for the decrypted master secret. Write the end
 *                         result here.
 * \param ms_ver           The message containing the encrypted master secret.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the master secret.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the master secret.
 */
void
decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod)
{
	mpz_t premaster;
	mpz_init(premaster);
	mpz_set_str(premaster, ms_ver->ps, 16);
	perform_rsa(decrypted_ms, premaster, key_exp, key_mod);
	mpz_clear(premaster);
}

/*
 * \brief                  Computes the master secret.
 *
 * \param ps               The premaster secret.
 * \param client_random    The random value from the client hello.
 * \param server_random    The random value from the server hello.
 * \param master_secret    A pointer to the final value of the master secret.
 *                         Write the end result here.
 */
void
compute_master_secret(int ps, int client_random, int server_random, char *master_secret)
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	unsigned char data[sizeof(int)];
	unsigned char data1[sizeof(int)];
	unsigned char data2[sizeof(int)];
	unsigned char data3[sizeof(int)];
	char master_secret0[16], master_secret1[16], master_secret2[16], master_secret3[16];

	memcpy(data, &ps, sizeof(ps));
	sha256_update(&ctx, data, (int) sizeof(data));

	memcpy(data1, &client_random, sizeof(client_random));
	sha256_update(&ctx, data1, (int) sizeof(data1));

	memcpy(data2, &server_random, sizeof(server_random));
	sha256_update(&ctx, data2, (int) sizeof(data2));

	memcpy(data3, &ps, sizeof(ps));
	sha256_update(&ctx, data3, (int) sizeof(data3));
	// unsigned char data[4*sizeof(int)];
	// memcpy(data, &ps, sizeof(ps));
	// memcpy(data+sizeof(ps), &client_random, sizeof(client_random));
	// memcpy(data+sizeof(client_random), &server_random, sizeof(server_random));
	// memcpy(data+sizeof(server_random), &ps, sizeof(ps));
	sha256_final(&ctx, (unsigned char*) master_secret);
}


/*
 * \brief                  Sends a message to the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to send
 *                         the message on.
 * \param msg              A pointer to the message to send.
 * \param msg_len          The length of the message in bytes.
 */
int
send_tls_message(int socketno, void *msg, int msg_len)
{
	// YOUR CODE HERE
	int n = 0;
	n = write(socketno, msg, (size_t) msg_len);
	if (n < 0){
	 	return ERR_FAILURE;
	}else{
	 	return ERR_OK;
	}
}

/*
 * \brief                  Receieves a message from the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to receive
 *                         the message on.
 * \param msg              A pointer to where to store the received message.
 * \param msg_len          The length of the message in bytes.
 * \param msg_type         The expected type of the message to receive.
 */
int
receive_tls_message(int socketno, void *msg, int msg_len, int msg_type)
{
	// YOUR CODE HERE
	// Need to deal with the case that receive message is ERROR message
	int n = 0;
	// Mesage length probabaly large than MAX_REc
	// Need while loop here
	void *msg_ptr = msg;
	int remain_bytes = msg_len;
	while (remain_bytes > MAX_RECEIVE_BYTES){
		n = read(socketno, msg_ptr, MAX_RECEIVE_BYTES);
		if (n < 0){
	 		return ERR_FAILURE;
	 	}
	 	remain_bytes -= MAX_RECEIVE_BYTES;
	 	msg_ptr += MAX_RECEIVE_BYTES;
	}
	n = read(socketno, msg_ptr, (size_t) remain_bytes);
	msg_ptr = NULL;
	if (n < 0){
	 	return ERR_FAILURE;
	}
	int *msg_type_int = msg;
	printf("Message Type: %d\n", *msg_type_int);
	if (msg_type != *msg_type_int) {
		return ERR_FAILURE;
	}
	return ERR_OK;
}


/*
 * \brief                Encrypts/decrypts a message using the RSA algorithm.
 *
 * \param result         a field to populate with the result of your RSA calculation.
 * \param message        the message to perform RSA on. (probably a cert in this case)
 * \param d              the encryption key from the key_file passed in through the
 *                       command-line arguments
 * \param n              the modulus for RSA from the modulus_file passed in through
 *                       the command-line arguments
 *
 * Fill in this function with your proj0 solution or see staff solutions.
 */
static void
perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n)
{
	int hex = 16;
	mpz_t zero, one, two, tmp;
	char zero_str[] = "0";
	char one_str[] = "1";
	char two_str[] = "2";

	mpz_init(zero);
	mpz_init(one);
	mpz_init(two);
	mpz_init(tmp);

	mpz_set_str(zero, zero_str, hex);
	mpz_set_str(one, one_str, hex);
	mpz_set_str(two, two_str, hex);
	mpz_set_str(tmp, zero_str, hex);
	
	// initilize result = 1;
	mpz_add(result, zero, one);

	while (mpz_cmp(d, zero) > 0){
		mpz_mod(tmp, d, two);
		if (mpz_cmp(tmp, one) == 0) {
			// result = (result * message) % n;
			mpz_mul(tmp, result, message);
			mpz_mod(result, tmp, n);
			// d--;
			mpz_sub(d, d, one);
		}
		// d = d/2;
		mpz_div(d, d, two);
		// message = (message * message) % n;
		mpz_mul(tmp, message, message);
		mpz_mod(message, tmp, n);
	}
	mpz_clear(zero);
	mpz_clear(one);
	mpz_clear(two);
	mpz_clear(tmp);
}


/* Returns a pseudo-random integer. */
static int
random_int()
{
	srand(time(NULL));
	return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void
mpz_get_ascii(char *output_str, mpz_t input)
{
	int i,j;
	char *result_str;
	result_str = mpz_get_str(NULL, HEX_BASE, input);
	i = 0;
	j = 0;
	while (result_str[i] != '\0') {
		output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
		//printf("%c\n", output_str[j]);
		j += 1;
		i += 2;
	}
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char
*hex_to_str(char *data, int data_len)
{
	int i;
	char *output_str = calloc(1+2*data_len, sizeof(char));
	for (i = 0; i < data_len; i += 1) {
		snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
	}
	return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
void
get_cert_exponent(mpz_t result, char *cert)
{
	char *srch, *srch2;
	char exponent[RSA_MAX_LEN/2];
	memset(exponent, 0, RSA_MAX_LEN/2);
	srch = strchr(cert, '\n');
	srch += 1;
	srch = strchr(srch, '\n');
	srch += 1;
	srch = strchr(srch, '\n');
	srch += 1;
	srch = strchr(srch, ':');
	srch += 2;
	srch2 = strchr(srch, '\n');
	strncpy(exponent, srch, srch2-srch);
	mpz_set_str(result, exponent, 0);
}

/* Return the public key modulus given the decrypted certificate as string. */
void
get_cert_modulus(mpz_t result, char *cert)
{
	char *srch, *srch2;
	char modulus[RSA_MAX_LEN/2];
	memset(modulus, 0, RSA_MAX_LEN/2);
	srch = strchr(cert, '\n');
	srch += 1;
	srch = strchr(srch, '\n');
	srch += 1;
	srch = strchr(srch, ':');
	srch += 2;
	srch2 = strchr(srch, '\n');
	strncpy(modulus, srch, srch2-srch);
	mpz_set_str(result, modulus, 0);
}

/* Prints the usage string for this program and exits. */
static void
usage()
{
	printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
	exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void
kill_handler(int signum)
{
	if (signum == SIGTERM) {
		cleanup();
	}
}

/* Converts the two input hex characters into an ascii char. */
static int
hex_to_ascii(char a, char b)
{
	int high = hex_to_int(a) * 16;
	int low = hex_to_int(b);
	return high + low;
}

/* Converts a hex value into an int. */
static int
hex_to_int(char a)
{
	if (a >= 97) {
		a -= 32;
	}
	int first = a / 16 - 3;
	int second = a % 16;
	int result = first*10 + second;
	if (result > 9) {
		result -= 1;
	}
	return result;
}

/* Closes files and exits the program. */
static void
cleanup()
{
	close(sockfd);
	exit(1);
}

// ====================== Additional Function ============================
unsigned long long assign_to_long(unsigned char* val_array){
	unsigned long long val = 0;
	int i = 0;
	while (i < SHA_BLOCK_SIZE){
		val <<= 8;
		val += (unsigned long long) val_array[i];
		i++;
	}
	return val;
}
//void convert_to_mpz_t(mpz_t result, )
