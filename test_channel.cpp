#include <cstdio>
#include <cstdlib>

int main() {
    const char* iface = "wlan1";
    char cmd[256];

    printf("[*] Testing channel change via system() call\n");

    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/iw dev %s set freq 5180 HT40+ 2>&1",
             iface);
    printf("[*] Running: %s\n", cmd);
    int r = system(cmd);
    printf("[*] Return code: %d\n", r);

    snprintf(cmd, sizeof(cmd), "/usr/sbin/iw dev %s info", iface);
    printf("[*] Interface info after change:\n");
    system(cmd);

    printf("\n[*] Testing 80MHz freq change\n");
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/iw dev %s set freq 5765 80 5775 2>&1",
             iface);
    printf("[*] Running: %s\n", cmd);
    r = system(cmd);
    printf("[*] Return code: %d\n", r);

    snprintf(cmd, sizeof(cmd), "/usr/sbin/iw dev %s info", iface);
    printf("[*] Interface info after change:\n");
    system(cmd);

    return 0;
}
