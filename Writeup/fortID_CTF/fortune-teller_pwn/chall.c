#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile unsigned int blessing = 0;

static void win(void) {
    char flag[128];

    FILE *f = fopen("flag.txt", "r");
    if (!f) {
        puts("flag.txt missing");
        exit(1);
    }

    fgets(flag, sizeof(flag), f);
    puts(flag);
    fclose(f);
}

static void read_line(char *buf, size_t size) {
    size_t i = 0;
    char c;

    while (i + 1 < size) {
        ssize_t r = read(0, &c, 1);
        if (r <= 0) {
            exit(0);
        }

        if (c == '\n') {
            break;
        }

        buf[i++] = c;
    }

    buf[i] = '\0';
}

static int read_choice(void) {
    char buf[8];

    read_line(buf, sizeof(buf));
    return atoi(buf);
}

static void ask_oracle(void) {
    char question[256];

    puts("Ask the oracle anything:");
    printf("> ");
    fflush(stdout);

    read_line(question, sizeof(question));

    puts("The oracle speaks:");
    printf(question);
    putchar('\n');
}

static void receive_blessing(void) {
    if (blessing == 0x1337) {
        puts("The stars are aligned.");
        win();
    } else {
        printf("You are not blessed yet. Current blessing: 0x%x\n", blessing);
    }
}

int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("=== Fortune Teller ===");

    while (1) {
        puts("");
        puts("1. Ask the oracle");
        puts("2. Receive blessing");
        puts("3. Leave");
        printf("> ");

        switch (read_choice()) {
            case 1:
                ask_oracle();
                break;
            case 2:
                receive_blessing();
                break;
            case 3:
                puts("The future fades away...");
                return 0;
            default:
                puts("The oracle does not understand.");
                break;
        }
    }
}
