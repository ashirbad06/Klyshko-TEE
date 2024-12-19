
#include "vars.h"

/* RA-TLS: on client, only need to register ra_tls_verify_callback_extended_der() for cert
 * verification. */
extern int (*ra_tls_verify_callback_extended_der_f)(uint8_t* der_crt, size_t der_crt_size,
                                                    struct ra_tls_verify_callback_results* results);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
extern void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(
    const char* mrenclave, const char* mrsigner, const char* isv_prod_id, const char* isv_svn));

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

//***$$$***
static ssize_t file_read(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "r");
    if (!f)
        return -errno;

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0) {
        int errsv = errno;
        fclose(f);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0)
        return -errno;

    return bytes;
}
//***$$$***

static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}

/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];

static bool g_verify_mrenclave   = false;
static bool g_verify_mrsigner    = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn     = false;

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
                                  const char* isv_prod_id, const char* isv_svn) {
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    if (g_verify_mrenclave && memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
        return -1;

    if (g_verify_mrsigner && memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
        return -1;

    if (g_verify_isv_prod_id &&
        memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
        return -1;

    if (g_verify_isv_svn && memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
        return -1;

    return 0;
}

/* RA-TLS: mbedTLS-specific callback to verify the x509 certificate */
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }
    return ra_tls_verify_callback_extended_der_f(crt->raw.p, crt->raw.len,
                                                 (struct ra_tls_verify_callback_results*)data);
}

char* addHex(const char* hex1, const char* hex2) {
    // Convert hex strings to unsigned long long integers
    unsigned long long num1 = strtoull(hex1, NULL, 16);
    unsigned long long num2 = strtoull(hex2, NULL, 16);

    // Add the two numbers
    unsigned long long sum = num1 + num2;

    // Allocate memory for the result string (16 characters + 1 for null terminator)
    char* result = (char*)malloc(17);
    if (result == NULL) {
        return NULL;  // Handle memory allocation failure
    }

    // Convert the sum back to a hexadecimal string
    snprintf(result, 17, "%016llx", sum);

    return result;
}

int ssl_client_setup_and_handshake(char* a, char* b, char* c, char* d, char* Player_MAC_Keys_p[],
                                   char* Player_MAC_Keys_2[], char* Seed) {
    printf("In client code\n");
    int no_of_parameters = 5;
    mbedtls_printf("Value of a: %s\n", a);
    int ret;
    size_t len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char* pers = "ssl_client1";

    char server_port[5];
    char server_ip[16];

    char* error;
    void* ra_tls_verify_lib                                          = NULL;
    ra_tls_verify_callback_extended_der_f                            = NULL;
    ra_tls_set_measurement_callback_f                                = NULL;
    struct ra_tls_verify_callback_results my_verify_callback_results = {0};

    //***$$$***
    void* ra_tls_attest_lib;
    int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size,
                                           uint8_t** der_crt, size_t* der_crt_size);

    uint8_t* der_key = NULL;
    uint8_t* der_crt = NULL;
    //***$$$***

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    //***$$$***
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    //***$$$***

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_printf("Failed to initialize PSA Crypto implementation: %d\n", (int)status);
        return 1;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO || MBEDTLS_SSL_PROTO_TLS1_3 */

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    //***$$$***
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);

    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf(
            "User requested RA-TLS attestation but cannot read SGX-specific file "
            "/dev/attestation/attestation_type\n");
        return 1;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib               = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    //***$$$***

    ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
    if (!ra_tls_verify_lib) {
        mbedtls_printf("%s\n", dlerror());
        mbedtls_printf(
            "User requested RA-TLS verification with DCAP inside SGX but cannot find "
            "lib\n");
        mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
        return 1;
    }

    if (ra_tls_verify_lib) {
        ra_tls_verify_callback_extended_der_f =
            dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_extended_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f =
            dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return 1;
        }
    }

    if (no_of_parameters > 2 && ra_tls_verify_lib) {
        if (no_of_parameters != 5) {
            mbedtls_printf(
                "USAGE: %s %s <expected mrenclave> <expected mrsigner>"
                " <expected isv_prod_id> <expected isv_svn>\n"
                "       (first two in hex, last two as decimal; set to 0 to ignore)\n",
                a, b);
            return 1;
        }

        mbedtls_printf(
            "[ using our own SGX-measurement verification callback"
            " (via command line options) ]\n");

        g_verify_mrenclave   = true;
        g_verify_mrsigner    = true;
        g_verify_isv_prod_id = true;
        g_verify_isv_svn     = true;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);

        if (!strcmp(a, "0")) {
            mbedtls_printf("  - ignoring MRENCLAVE\n");
            g_verify_mrenclave = false;
        } else if (parse_hex(a, g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0) {
            mbedtls_printf("Cannot parse MRENCLAVE!\n");
            return 1;
        }

        if (!strcmp(b, "0")) {
            mbedtls_printf("  - ignoring MRSIGNER\n");
            g_verify_mrsigner = false;
        } else if (parse_hex(b, g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0) {
            mbedtls_printf("Cannot parse MRSIGNER!\n");
            return 1;
        }

        if (!strcmp(c, "0")) {
            mbedtls_printf("  - ignoring ISV_PROD_ID\n");
            g_verify_isv_prod_id = false;
        } else {
            errno                = 0;
            uint16_t isv_prod_id = (uint16_t)strtoul(c, NULL, 10);
            if (errno) {
                mbedtls_printf("Cannot parse ISV_PROD_ID!\n");
                return 1;
            }
            memcpy(g_expected_isv_prod_id, &isv_prod_id, sizeof(isv_prod_id));
        }

        if (!strcmp(d, "0")) {
            mbedtls_printf("  - ignoring ISV_SVN\n");
            g_verify_isv_svn = false;
        } else {
            errno            = 0;
            uint16_t isv_svn = (uint16_t)strtoul(d, NULL, 10);
            if (errno) {
                mbedtls_printf("Cannot parse ISV_SVN\n");
                return 1;
            }
            memcpy(g_expected_isv_svn, &isv_svn, sizeof(isv_svn));
        }
    } else if (ra_tls_verify_lib) {
        mbedtls_printf(
            "[ using default SGX-measurement verification callback"
            " (via RA_TLS_* environment variables) ]\n");
        (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */
    } else {
        mbedtls_printf("[ using normal TLS flows ]\n");
    }

    for (other_player_number = number_of_players - 1;
         other_player_number >= player_number_defined + 1; other_player_number--) {
        printf("\n  . Seeding the random number generator...");
        //  fflush(stdout);

        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char*)pers, strlen(pers));
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
            goto exit;
        }

        mbedtls_printf(" ok\n");

        //***$$$***
        if (ra_tls_attest_lib) {
            mbedtls_printf(
                "\n  . Creating the RA-TLS server cert and key (using \"%s\" as "
                "attestation type)...",
                attestation_type_str);
            fflush(stdout);

            size_t der_key_size;
            size_t der_crt_size;

            ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt,
                                                     &der_crt_size);
            if (ret != 0) {
                mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
                goto exit;
            }

            ret = mbedtls_x509_crt_parse(&clicert, (unsigned char*)der_crt, der_crt_size);
            if (ret != 0) {
                mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
                goto exit;
            }

            ret = mbedtls_pk_parse_key(&pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL,
                                       0, mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0) {
                mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
                goto exit;
            }

            mbedtls_printf(" ok\n");
        }

        //***$$$***
        char* ip_address      = kii_endpoints[other_player_number];
        const char* colon_pos = strrchr(kii_endpoints[other_player_number], ':');
        size_t ip_length      = colon_pos - ip_address;
        if (colon_pos != NULL) {
            strncpy(server_port, colon_pos + 1, 4);  // Copy the last 4 characters (port)
            strncpy(server_ip, ip_address, ip_length);
            server_port[4]       = '\0';  // Null-terminate the string
            server_ip[ip_length] = '\0';
        } else {
            printf("Error: Invalid endpoint format. No colon found.\n");
        }

        printf("Extracted port at start in client: %s\n", server_port);  // Output should be "4444"
        printf("Extracted ip at start in client: %s\n", server_ip);

        //***$$$***

        mbedtls_printf("  . Connecting to tcp/%s/%s...", server_ip, server_port);
        fflush(stdout);

        // ret = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        //     goto exit;
        // }

        while (1) {
            ret = mbedtls_net_connect(&server_fd, server_ip, server_port, MBEDTLS_NET_PROTO_TCP);
            if (ret == 0)
                break;
            else {
                mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
                // mbedtls_printf("Retrying in %d seconds...\n", RETRY_DELAY);

                // mbedtls_net_free(&server_fd);
                // mbedtls_net_init(&server_fd);
                sleep(RETRY_DELAY);
            }
        }

        mbedtls_printf(" ok\n");

        mbedtls_printf("  . Setting up the SSL/TLS structure...");
        fflush(stdout);

        ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
            goto exit;
        }

        mbedtls_printf(" ok\n");

        fflush(stdout);

        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_printf(" ok\n");

        if (ra_tls_verify_lib) {
            /* use RA-TLS verification callback; this will overwrite CA chain set up above */
            mbedtls_printf("  . Installing RA-TLS callback ...");
            mbedtls_ssl_conf_verify(&conf, &my_verify_callback, &my_verify_callback_results);
            mbedtls_printf(" ok\n");
        }

        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

        //***$$$***
        ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
            goto exit;
        }
        //***$$$***

        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_ssl_set_hostname(&ssl, server_ip);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
            goto exit;
        }

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        mbedtls_printf("  . Performing the SSL/TLS handshake...");
        fflush(stdout);

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
                mbedtls_printf(
                    "  ! ra_tls_verify_callback_results:\n"
                    "    attestation_scheme=%d, err_loc=%d, \n",
                    my_verify_callback_results.attestation_scheme,
                    my_verify_callback_results.err_loc);
                switch (my_verify_callback_results.attestation_scheme) {
                    case RA_TLS_ATTESTATION_SCHEME_DCAP:
                        mbedtls_printf(
                            "    dcap.func_verify_quote_result=0x%x, "
                            "dcap.quote_verification_result=0x%x\n\n",
                            my_verify_callback_results.dcap.func_verify_quote_result,
                            my_verify_callback_results.dcap.quote_verification_result);
                        break;
                    default:
                        mbedtls_printf("  ! unknown attestation scheme!\n\n");
                        break;
                }

                goto exit;
            }
        }

        mbedtls_printf(" ok\n");

        mbedtls_printf("  . Verifying peer X.509 certificate...");

        flags = mbedtls_ssl_get_verify_result(&ssl);
        if (flags != 0) {
            char vrfy_buf[512];
            mbedtls_printf(" failed\n");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            mbedtls_printf("%s\n", vrfy_buf);

            /* verification failed for whatever reason, fail loudly */
            goto exit;
        } else {
            mbedtls_printf(" ok\n");
        }

        mbedtls_printf("  > Write to server:");
        fflush(stdout);

        len = sprintf((char*)buf, GET_REQUEST);

        PlayerInfo msg    = PLAYER_INFO__INIT;
        msg.kii_job_id    = "1920bb26-dsee-dzfw-vdsdsa14fds4";  // Example initialization
        msg.player_number = player_number_defined;              // Example initialization

        // Buffer for serialized data
        unsigned playlen = player_info__get_packed_size(&msg);
        if (playlen == 0) {
            fprintf(stderr, "Packing or serialization error\n");
        }

        void* buff = malloc(playlen);
        if (!buff) {
            fprintf(stderr, "Memory allocation error\n");
        }

        player_info__pack(&msg, buff);
        fprintf(stderr, "Writing %d serialized bytes\n", playlen);
        mbedtls_ssl_write(&ssl, buff, playlen);

        // code for packing the macshares and sending over the TLS dconnection again to the server
        SecretShare message   = SECRET_SHARE__INIT;
        message.mackeyshare_2 = Player_MAC_Keys_2[player_number_defined];
        message.mackeyshare_p = Player_MAC_Keys_p[player_number_defined];
        message.seeds         = Seed;
        unsigned lent         = secret_share__get_packed_size(&message);
        if (lent == 0) {
            fprintf(stderr, "packing or serialization error");
        }
        void* buffer = malloc(lent);
        if (!buffer) {
            fprintf(stderr, "Memory allocation error\n");
        }

        secret_share__pack(&message, buffer);
        fprintf(stderr, "Writing %d serialized bytes\n", lent);
        mbedtls_ssl_write(&ssl, buffer, lent);
        // EOC for sending
        //  code for unpacking the files from server side and result displaying
        uint8_t secret_buffer[MAX_MSG_SIZE];
        size_t secret_len = mbedtls_ssl_read(&ssl, secret_buffer, sizeof(secret_buffer));

        if (secret_len <= 0) {
            fprintf(stderr, "SSL read error: %ld\n", secret_len);
        }
        SecretShare* secret_message;
        secret_message = secret_share__unpack(NULL, secret_len, secret_buffer);
        if (secret_message == NULL) {
            fprintf(stderr, "Error unpacking incoming message\n");
        }

        // Display the message's fields
        printf("Received: mackeyshare_2=%s", secret_message->mackeyshare_2);  // required field
        printf("  mackeyshare_p=%s\n", secret_message->mackeyshare_p);
        printf("  seeds=%s\n", secret_message->seeds);

        // Perform operations
        // Seed = addHex(Seed, secret_message->seeds);
        memcpy(Seed, addHex(Seed, secret_message->seeds), KEY_LENGTH);
        printf("ADDED SEED IS : %s\n", Seed);
        memcpy(Player_MAC_Keys_p[other_player_number], secret_message->mackeyshare_p, KEY_LENGTH);
        memcpy(Player_MAC_Keys_2[other_player_number], secret_message->mackeyshare_2, KEY_LENGTH);
        // Free the unpacked message
        secret_share__free_unpacked(secret_message, NULL);
        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_free(&ssl);
        mbedtls_net_free(&server_fd);
        mbedtls_x509_crt_free(&clicert);
        mbedtls_pk_free(&pkey);
        free(der_key);
        free(der_crt);
        exit_code = MBEDTLS_EXIT_SUCCESS;
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

// exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }

#endif
    if (ra_tls_verify_lib)
        dlclose(ra_tls_verify_lib);

    // mbedtls_net_free(&server_fd);

    // mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    //***$$$***
    // mbedtls_x509_crt_free(&clicert);
    // mbedtls_pk_free(&pkey);
    // free(der_key);
    // free(der_crt);
    //***$$$***

#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO || MBEDTLS_SSL_PROTO_TLS1_3 */

    return exit_code;
}