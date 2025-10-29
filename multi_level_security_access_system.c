/*
 * Multi-Level Security Access System (Keil/C89-friendly)
 * Target MCU: LPC2124
 * Single-file version: all peripheral stubs + main logic
 *
 * Notes:
 *  - Uses C89-compatible declarations (no 'for (int i=...)' or mixed declarations)
 *  - Delay uses simple busy loops (adjust inner count to tune timing)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================= STUB PERIPHERALS ========================= */

/* LCD */
void lcd_init(void) { printf("[LCD] Initialized\n"); }
void lcd_clear(void) { printf("\n[LCD] CLEAR\n"); }
void lcd_puts(const char *s) { printf("[LCD] %s\n", s); }
void lcd_putc(char c) { printf("%c", c); }

/* Delay (Keil-friendly busy loop) */
void delay_ms(unsigned int ms) {
    unsigned int i, j;
    for (i = 0; i < ms; i++) {
        for (j = 0; j < 6000; j++) {
            /* nop - adjust count for MCU clock */
        }
    }
}

/* Keypad */
void keypad_init(void) { printf("[KEYPAD] Initialized\n"); }
int keypad_wait_for_key(void) {
    char c;
    printf("[KEYPAD] Enter key: ");
    scanf(" %c", &c);
    return (int)c;
}
int keypad_getstring_with_timeout(char *buf, int maxlen, unsigned int timeout_ms) {
    printf("[KEYPAD] Enter input (timeout %u ms): ", timeout_ms);
    scanf("%s", buf);
    return (int)strlen(buf);
}

/* UART */
void uart0_init(unsigned long baud) { printf("[UART0] Init at %lu baud\n", baud); }
void uart0_send_string(const char *s) { printf("[UART0 TX] %s\n", s); }

/* I2C / EEPROM (in-memory simulation) */
#define EEPROM_SIZE 4096
static unsigned char eeprom_memory[EEPROM_SIZE];

void i2c_init(void) { printf("[I2C] Initialized\n"); }
void eeprom_init(void) {
    unsigned int k;
    for (k = 0; k < EEPROM_SIZE; k++) eeprom_memory[k] = 0xFF;
    printf("[EEPROM] Ready\n");
}
int eeprom_read_bytes(unsigned int addr, unsigned char *buf, unsigned int len) {
    if (addr + len > EEPROM_SIZE) return -1;
    {
        unsigned int p;
        for (p = 0; p < len; p++) buf[p] = eeprom_memory[addr + p];
    }
    return 0;
}
int eeprom_write_bytes(unsigned int addr, const unsigned char *buf, unsigned int len) {
    if (addr + len > EEPROM_SIZE) return -1;
    {
        unsigned int p;
        for (p = 0; p < len; p++) eeprom_memory[addr + p] = buf[p];
    }
    return 0;
}

/* RFID (stub) */
void rfid_init(void) { printf("[RFID] Ready\n"); }
int rfid_read_blocking(unsigned char *buf, int len, unsigned int timeout_ms) {
    char temp[32];
    int i;
    printf("[RFID] Enter card ID: ");
    scanf("%s", temp);
    /* Build framed packet: STX ... ETX */
    if (len < 3) return -1;
    for (i = 0; i < len; i++) buf[i] = 0;
    buf[0] = 0x02;
    /* copy payload (limit to len-2) */
    for (i = 0; i < (len - 2) && temp[i] != '\0'; i++) {
        buf[1 + i] = (unsigned char)temp[i];
    }
    buf[1 + i] = 0x03;
    return len;
}

/* Fingerprint (stub) */
void fingerprint_init(void) { printf("[FP] Sensor Ready\n"); }
int fp_search(void) {
    int matched;
    printf("[FP] Enter match result (1=match,0=fail): ");
    scanf("%d", &matched);
    return (matched ? 1 : -1);
}
int fp_enroll(int id) {
    printf("[FP] Enroll user %d: Done\n", id);
    return 0;
}
int fp_delete(int id) {
    printf("[FP] Delete user %d: Done\n", id);
    return 0;
}

/* Motor (stub) */
void motor_init(void) { printf("[MOTOR] Ready\n"); }
void motor_open(void) { printf("[MOTOR] Opening (CW)\n"); }
void motor_close(void) { printf("[MOTOR] Closing (CCW)\n"); }

/* Timer (stub) */
void timer_init(void) { printf("[TIMER] Started\n"); }

/* ========================= APPLICATION LOGIC ========================= */

/* Configuration */
#define MAX_USERS 50
#define PASSWORD_MAX_LEN 8
#define CARD_ID_LEN 10
#define EEPROM_PASSWORD_BASE_ADDR 0x0000
#define PASSWORD_EEPROM_SLOT_SIZE 16
#define USER_SLOT_ADDR(uid) (EEPROM_PASSWORD_BASE_ADDR + ((uid) * PASSWORD_EEPROM_SLOT_SIZE))
#define PASSWORD_ENTRY_TIMEOUT_MS 15000
#define MAX_PASSWORD_ATTEMPTS 3
#define MAX_FP_ATTEMPTS 3

/* Globals */
static char entered_password[PASSWORD_MAX_LEN + 1];
static char stored_password[PASSWORD_MAX_LEN + 1];
static char rfid_card_string[CARD_ID_LEN + 1];

/* Prototypes */
static int check_rfid_and_get_userid(char *card_buf);
static int verify_password_for_user(unsigned char user_id);
static int do_fingerprint_search(unsigned char *matched_id);
static void door_open_sequence(void);

/* Main */
int main(void) {
    unsigned char matched_fp_id = 0xFF;

    /* Init */
    lcd_init();
    uart0_init(9600);
    keypad_init();
    i2c_init();
    eeprom_init();
    rfid_init();
    fingerprint_init();
    motor_init();
    timer_init();

    lcd_clear();
    lcd_puts("Multi-Level Security\nSystem Ready");

    while (1) {
        int password_verified;
        int fingerprint_verified;
        int attempt;

        /* Clear card buffer */
        {
            int k;
            for (k = 0; k < CARD_ID_LEN; k++) rfid_card_string[k] = '\0';
        }

        lcd_clear();
        lcd_puts("Place RFID card...");

        if (check_rfid_and_get_userid(rfid_card_string) == 0) {
            unsigned char user_id;
            user_id = (unsigned char)atoi(rfid_card_string);
            if (user_id >= MAX_USERS) {
                lcd_clear();
                lcd_puts("Card not registered\nAccess Denied");
                delay_ms(1500);
                continue;
            }

            /* PASSWORD: up to MAX_PASSWORD_ATTEMPTS */
            password_verified = 0;
            for (attempt = 1; attempt <= MAX_PASSWORD_ATTEMPTS; attempt++) {
                char msg[32];
                lcd_clear();
                /* prepare message - use sprintf (ensure msg declared at top of block) */
                sprintf(msg, "Enter Password\nAttempt %d/3", attempt);
                lcd_puts(msg);

                if (verify_password_for_user(user_id)) {
                    password_verified = 1;
                    break;
                } else {
                    if (attempt < MAX_PASSWORD_ATTEMPTS) {
                        lcd_clear();
                        lcd_puts("Wrong Password\nTry Again");
                        delay_ms(1000);
                    } else {
                        lcd_clear();
                        lcd_puts("Password Failed\nAccess Denied");
                        delay_ms(1500);
                    }
                }
            }
            if (!password_verified) continue;

            /* FINGERPRINT: up to MAX_FP_ATTEMPTS */
            fingerprint_verified = 0;
            for (attempt = 1; attempt <= MAX_FP_ATTEMPTS; attempt++) {
                char msg[32];
                lcd_clear();
                sprintf(msg, "Place Finger\nAttempt %d/3", attempt);
                lcd_puts(msg);

                if (do_fingerprint_search(&matched_fp_id)) {
                    fingerprint_verified = 1;
                    break;
                } else {
                    if (attempt < MAX_FP_ATTEMPTS) {
                        lcd_clear();
                        lcd_puts("Fingerprint Fail\nTry Again");
                        delay_ms(1000);
                    } else {
                        lcd_clear();
                        lcd_puts("Access Denied");
                        delay_ms(1500);
                    }
                }
            }
            if (!fingerprint_verified) continue;

            /* Access granted */
            lcd_clear();
            lcd_puts("All 3 Levels OK\nOpening Door");
            door_open_sequence();
            delay_ms(1000);
        }

        delay_ms(500);
    }

    /* unreachable */
    return 0;
}

/* ========== helper functions ========== */

/* Read RFID framed packet and extract payload string */
static int check_rfid_and_get_userid(char *card_buf) {
    unsigned char raw[CARD_ID_LEN];
    int rc;
    int i, j;

    rc = rfid_read_blocking(raw, CARD_ID_LEN, 20000);
    if (rc != CARD_ID_LEN) return -1;
    if (raw[0] != 0x02 || raw[CARD_ID_LEN - 1] != 0x03) return -1;

    /* extract payload bytes 1 .. CARD_ID_LEN-2 */
    j = 0;
    for (i = 1; i < CARD_ID_LEN - 1 && j < CARD_ID_LEN - 2; i++, j++) {
        card_buf[j] = (char)raw[i];
    }
    card_buf[j] = '\0';
    return 0;
}

/* Verify password for user by reading EEPROM and comparing with keypad input */
static int verify_password_for_user(unsigned char user_id) {
    unsigned int eeprom_addr;
    int res;
    int k;

    eeprom_addr = USER_SLOT_ADDR(user_id);
    /* clear stored_password */
    for (k = 0; k <= PASSWORD_MAX_LEN; k++) stored_password[k] = '\0';

    res = eeprom_read_bytes(eeprom_addr, (unsigned char *)stored_password, PASSWORD_MAX_LEN);
    stored_password[PASSWORD_MAX_LEN] = '\0';

    if (res != 0) {
        lcd_puts("EEPROM Read Err");
        delay_ms(1000);
        return 0;
    }

    if ((unsigned char)stored_password[0] == 0xFF || stored_password[0] == '\0') {
        lcd_puts("No Password Set\nContact Admin");
        delay_ms(1500);
        return 0;
    }

    /* clear entered_password */
    for (k = 0; k <= PASSWORD_MAX_LEN; k++) entered_password[k] = '\0';

    keypad_getstring_with_timeout(entered_password, PASSWORD_MAX_LEN, PASSWORD_ENTRY_TIMEOUT_MS);

    if (strncmp(entered_password, stored_password, PASSWORD_MAX_LEN) == 0) {
        return 1;
    } else {
        return 0;
    }
}

/* Fingerprint search wrapper */
static int do_fingerprint_search(unsigned char *matched_id) {
    int res;
    res = fp_search();
    if (res >= 0) {
        *matched_id = (unsigned char)res;
        return 1;
    }
    return 0;
}

/* Motor open/close sequence */
static void door_open_sequence(void) {
    motor_open();
    delay_ms(3000);
    motor_close();
    lcd_puts("Door Closed");
}
