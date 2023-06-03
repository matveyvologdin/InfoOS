extern "C" int kmain();
__declspec(naked) void startup()
{
    __asm call kmain;
}

void on_key(int scan_code);
void on_key_backspace();
void on_key_enter();
void call_command();
void command_handler(char* str);
int strcmp(char* s1, char* s2);
void out_char(char letter);
void out_str(const char* ptr);
void cursor_moveto();
void clear_scr();
void next_line();
static inline void outw(unsigned short port, unsigned short data);
void print_time(unsigned int time);
unsigned int get_time(unsigned char mode);
unsigned int boot_time(unsigned char* address);
static inline unsigned int rdtsc(int* r1, int* r2);
void strcpy(char* destination, char* source);
char* add(char* str1, char* str2);
char* umn(char* str, int pow);
//Основные функции
void call_info();
void call_help();
void call_ticks();
void call_loadtime();
void call_curtime();
void call_uptime();
void call_cpuid();
void call_shutdown();

#define TIMEZONE 3

int cur_line = 0;
int cur_col = 0;
int cur_color = 0x07;
const char SCAN_CODES[] = "\0\0001234567890-\0\0\0qwertyuiop\0\0\0\0asdfghjkl\0\0\0\0\0zxcvbnm\0\0/\0*\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0+ ";
#define VIDEO_BUF_PTR 0xB8000
#define CURSOR_PORT 0x3D4
#define VIDEO_WIDTH 80
#define VIDEO_HEIGHT 25
#define MAX_STR 41
#define KEY_BACKSPACE  14
#define KEY_ENTER 28

#define IDT_TYPE_INTR (0x0E)
#define IDT_TYPE_TRAP (0x0F)
// Селектор секции кода, установленный загрузчиком ОС
#define GDT_CS 0x8

#define PIC1_PORT (0x20)
// Структура описывает данные об обработчике прерывания
#pragma pack(push, 1) // Выравнивание членов структуры запрещено

struct idt_entry
{
    unsigned short base_lo; // Младшие биты адреса обработчика
    unsigned short segm_sel; // Селектор сегмента кода
    unsigned char always0; // Этот байт всегда 0
    unsigned char flags; // Флаги тип. Флаги: P, DPL, Типы - это константы - IDT_TYPE...
    unsigned short base_hi; // Старшие биты адреса обработчика
};

// Структура, адрес которой передается как аргумент команды lidt
struct idt_ptr
{
    unsigned short limit;
    unsigned int base;
};

#pragma pack(pop)

struct idt_entry g_idt[256]; // Реальная таблица IDT
struct idt_ptr g_idtp;

__declspec(naked) void default_intr_handler()
{
    __asm {
        pusha
    }

    __asm {
        popa
        iretd
    }
}

typedef void (*intr_handler)();
void intr_reg_handler(int num, unsigned short segm_sel, unsigned short
    flags, intr_handler hndlr)
{
    unsigned int hndlr_addr = (unsigned int)hndlr;
    g_idt[num].base_lo = (unsigned short)(hndlr_addr & 0xFFFF);
    g_idt[num].segm_sel = segm_sel;
    g_idt[num].always0 = 0;
    g_idt[num].flags = flags;
    g_idt[num].base_hi = (unsigned short)(hndlr_addr >> 16);
}
// Функция инициализации системы прерываний: заполнение массива с адресами
//обработчиков
void intr_init()
{
    int i;
    int idt_count = sizeof(g_idt) / sizeof(g_idt[0]);
    for (i = 0; i < idt_count; i++)
        intr_reg_handler(i, GDT_CS, 0x80 | IDT_TYPE_INTR,
            default_intr_handler); // segm_sel=0x8, P=1, DPL=0, Type=Intr
}

void intr_start()
{
    int idt_count = sizeof(g_idt) / sizeof(g_idt[0]);
    g_idtp.base = (unsigned int)(&g_idt[0]);
    g_idtp.limit = (sizeof(struct idt_entry) * idt_count) - 1;
    __asm {
        lidt g_idtp
    }
    //__lidt(&g_idtp);
}

void intr_enable()
{
    __asm sti;
}

void intr_disable()
{
    __asm cli;
}

__inline unsigned char inb(unsigned short port)
{
    unsigned char data;
    __asm {
        push dx
        mov dx, port
        in al, dx
        mov data, al
        pop dx
    }
    return data;
}

__inline void outb(unsigned short port, unsigned char data)
{
    __asm {
        push dx
        mov dx, port
        mov al, data
        out dx, al
        pop dx
    }
}

void keyb_process_keys()
{
    // Проверка что буфер PS/2 клавиатуры не пуст (младший бит
    // присутствует)
    if (inb(0x64) & 0x01)
    {
        unsigned char scan_code;
        unsigned char state;
        scan_code = inb(0x60); // Считывание символа с PS/2 клавиатуры
        if (scan_code < 128) // Скан-коды выше 128 - это отпускание клавиши
            on_key(scan_code);
    }
}

__declspec(naked) void keyb_handler()
{
    __asm pusha;
    // Обработка поступивших данных
    keyb_process_keys();
    // Отправка контроллеру 8259 нотификации о том, что прерывание
    // обработано.Если не отправлять нотификацию, то контроллер не будет посылать
    // новых сигналов о прерываниях до тех пор, пока ему не сообщать что
    // прерывание обработано.
    outb(PIC1_PORT, 0x20);
    __asm {
        popa
        iretd
    }
}

void keyb_init()
{
    // Регистрация обработчика прерывания
    intr_reg_handler(0x09, GDT_CS, 0x80 | IDT_TYPE_INTR, keyb_handler);
    // segm_sel=0x8, P=1, DPL=0, Type=Intr
    // Разрешение только прерываний клавиатуры от контроллера 8259
    outb(PIC1_PORT + 1, 0xFF ^ 0x02); // 0xFF - все прерывания, 0x02 - бит IRQ1(клавиатура).
        // Разрешены будут только прерывания, чьи биты установлены в 0
}

void on_key(int scan_code)
{
    switch (scan_code)
    {
    case KEY_BACKSPACE:
        on_key_backspace();
        break;
    case KEY_ENTER:
        on_key_enter();
        break;
    default:
    {
        out_char(SCAN_CODES[scan_code]);
    }
    }
}

void on_key_backspace()
{
    if (cur_col == 0)
        return;
    cur_col--;
    unsigned char* video_buf = (unsigned char*)VIDEO_BUF_PTR;
    video_buf += 2 * (VIDEO_WIDTH * cur_line + cur_col);
    video_buf[0] = ' ';
    cursor_moveto();
}

void on_key_enter()
{
    if (cur_line == 24)
    {
        clear_scr();
        cur_col = 0;
        cur_line = 0;
        cursor_moveto();
        call_command();
        return;
    }
    cur_col = 0;
    cur_line++;
    cursor_moveto();
    call_command();
}

void call_command()
{
    unsigned char* video_buf = (unsigned char*)VIDEO_BUF_PTR;
    video_buf += 2 * (VIDEO_WIDTH * (cur_line - 1));
    char str[MAX_STR];
    for (int i = 0; i < 40; i++)
        str[i] = video_buf[2 * i];
    str[MAX_STR - 1] = '\0';
    command_handler(str);
    char info[MAX_STR] = "info";
    char help[MAX_STR] = "help";
    char clear[MAX_STR] = "clear";
    char ticks[MAX_STR] = "ticks";
    char loadtime[MAX_STR] = "loadtime";
    char curtime[MAX_STR] = "curtime";
    char uptime[MAX_STR] = "uptime";
    char cpuid[MAX_STR] = "cpuid";
    char shutdown[MAX_STR] = "shutdown";
    if (strcmp(str, info) == 1)
        call_info();
    else if (strcmp(str, help) == 1)
        call_help();
    else if (strcmp(str, clear) == 1)
        clear_scr();
    else if (strcmp(str, ticks) == 1)
        call_ticks();
    else if (strcmp(str, loadtime) == 1)
        call_loadtime();
    else if (strcmp(str, curtime) == 1)
        call_curtime();
    else if (strcmp(str, uptime) == 1)
        call_uptime();
    else if (strcmp(str, cpuid) == 1)
        call_cpuid();
    else if (strcmp(str, shutdown) == 1)
        call_shutdown();
    else
        out_str("Invalid command");
}

void command_handler(char* str)
{
    for (int i = MAX_STR; i >= 1; i--)
    {
        if (str[i - 1] == ' ' && (str[i] == ' ' || str[i] == '\0'))
        {
            for (int j = i - 1; j < MAX_STR; j++)
                str[j] = str[j + 1];
        }
    }
    while (str[0] == '\0' || str[0] == ' ')
        for (int i = 0; i < MAX_STR - 1; i++)
            str[i] = str[i + 1];
}

int strcmp(char* s1, char* s2)
{
    for (int i = 0; i < MAX_STR; i++)
        if (s1[i] != s2[i])
            return 0;
    return 1;
}

void call_info()
{
    out_str("Vologdin Matvey 4851003/2 IKiZI SPbSTU 2022");
    out_str("Yasm, Intel syntax and Microsoft C compiler");
}

void call_help()
{
    out_str("info - Information about author and development tools");
    out_str("help - Show information about available commands");
    out_str("clear - Clear the screen");
    out_str("ticks - Displays the number of ticks since system startup");
    out_str("loadtime - Show time, when OS started");
    out_str("curtime - Show the current time");
    out_str("uptime - Displays the total system uptime");
    out_str("cpuid - Specifies the processor model");
    out_str("shutdown - Shutdown computer");
}

void call_ticks()
{
    out_str("Number of ticks:");
    int edx, eax;
    unsigned int bit = 0, offset, tmp, c_flag = 0, k;
    unsigned int ticks = rdtsc(&eax, &edx);
    char str[21];
    char res[21];
    for (int i = 0; i < 19; i++)
        str[i] = '0';
    str[19] = '1';
    str[20] = '\0';
    for (int i = 0; i < 20; i++)
        res[i] = '0';
    res[20] = '\0';
    while (bit < 64)
    {
        if (bit < 32)
        {
            offset = 1 << bit;

            if (offset & eax)
            {
                strcpy(str, umn(str, bit));
                strcpy(res, add(res, str));
            }
        }
        else
        {
            offset = 1 << (bit - 32);
            if (offset & edx)
            {
                strcpy(str, umn(str, bit));
                strcpy(res, add(res, str));
            }
        }
        bit++;
    }
    k = 0;
    while (res[k] == '0')
        k++;
    while (k < 20)
    {
        out_char(res[k]);
        k++;
    }
    next_line();
}

void strcpy(char* destination, char* source)
{
    int i = 0;
    while (source[i] != '\0')
    {
        destination[i] = source[i];
        i++;
    }
    destination[i] = '\0';
}

char* add(char* str1, char* str2)
{
    int flag_c = 0, t1, t2;
    for (int i = 19; i >= 0; i--)
    {
        t1 = str1[i] - '0';
        t2 = str2[i] - '0';
        str1[i] = (t1 + t2 + flag_c) % 10 + '0';
        flag_c = (t1 + t2 + flag_c) / 10;
    }
    return str1;
}

char* umn(char* str, int pow)
{
    char tmp[21], dop[21];
    int cur_dig, t, flag_c = 0;
    tmp[20] = '\0';
    tmp[19] = '1';
    for (int i = 0; i < 19; i++)
        tmp[i] = '0';
    while (pow > 0)
    {
        cur_dig = 19;
        flag_c = 0;
        while (cur_dig >= 0)
        {
            t = tmp[cur_dig] - '0';
            tmp[cur_dig] = (t + t) % 10 + '0' + flag_c;
            flag_c = (t + t + flag_c) / 10;
            cur_dig--;
        }
        pow--;
    }
    return tmp;
}

void call_loadtime()
{
    out_str("Loadtime:");
    unsigned int time = boot_time((unsigned char*)(0x00001000));
    print_time(time);
    out_char(':');
    time = boot_time((unsigned char*)(0x00001100));
    print_time(time);
    out_char(':');
    time = boot_time((unsigned char*)(0x00001200));
    print_time(time);
    next_line();
}

unsigned int boot_time(unsigned char* address)
{
    unsigned char* memory = (unsigned char*)address;
    unsigned char x = memory[0];
    unsigned int answer = x - 6 * (x >> 4);
    if ((int)address == 0x00001000)
    {
        answer = answer + TIMEZONE;
        answer = answer % 24;
    }
    return answer;
}

void call_curtime()
{
    out_str("Current time:");
    print_time(get_time(4));
    out_char(':');
    print_time(get_time(2));
    out_char(':');
    print_time(get_time(0));
    next_line();
}

void print_time(unsigned int time)
{
    unsigned int high = time / 10;
    char c_high = high + '0';
    out_char(c_high);
    unsigned int low = time % 10;
    char c_low = low + '0';
    out_char(c_low);
}

unsigned int get_time(unsigned char mode)
{
    outb(0x70, mode);
    unsigned char x = inb(0x71);
    unsigned int answer = x - 6 * (x >> 4);
    if (mode == 4)
    {
        answer += TIMEZONE;
        answer = answer % 24;
    }
    return answer;
}

void call_uptime()
{
    out_str("Uptime:");
    unsigned int time = boot_time((unsigned char*)(0x00001000));
    print_time(get_time(4) - time);
    out_char(':');
    time = boot_time((unsigned char*)(0x00001100));
    print_time(get_time(2) - time);
    out_char(':');
    time = boot_time((unsigned char*)(0x00001200));
    print_time(get_time(0) - time);
    next_line();
}


void call_cpuid()
{
    int id;
    __asm {
        xor eax, eax
        cpuid
        mov id, ebx
    }
    if (id == 0x756E6547)
        out_str("VendorId: GenuineIntel");
    else if (id == 0x68747541)
        out_str("VendorId: AuthenticAMD");
    else if (id == 0x69727943)
        out_str("VendorId: CyrixInstead");
    else if (id == 0x746E6543)
        out_str("VendorId: CentaurHauls");
    else if (id == 0x20536953)
        out_str("VendorId: SiS SiS SiS");
    else if (id == 0x4778654E)
        out_str("VendorId: NexGenDriven");
    else if (id == 0x756E6547)
        out_str("VendorId: GenuineTMx86");
    else if (id == 0x65736952)
        out_str("VendorId: RiseRiseRise");
    else if (id == 0x20434D55)
        out_str("VendorId: UMC UMC UMC");
    else if (id == 0x646F6547)
        out_str("VendorId: Geode by NSC");
    else out_str("VendorId: Unknown");
}

void call_shutdown()
{
    outw(0x0604, 0x2000);
}

static inline unsigned int rdtsc(int* r1, int* r2)
{
    int tmp1, tmp2;
    __asm {
        rdtsc
        mov tmp1, eax
        mov tmp2, edx
    }
    *(r1) = tmp1;
    *(r2) = tmp2;
    return 1;
}

static inline void outw(unsigned short port, unsigned short data)
{
    __asm {
        push dx
        mov dx, port
        mov ax, data
        out dx, ax
        pop dx
    }
}

void out_char(char letter)
{
    if (cur_col > 39)
        return;
    unsigned char* video_buf = (unsigned char*)VIDEO_BUF_PTR;
    video_buf += 2 * (VIDEO_WIDTH * cur_line + cur_col);
    video_buf[0] = letter;
    video_buf[1] = cur_color;
    cur_col++;
    cursor_moveto();
}

void out_str(const char* ptr)
{
    cur_col = 0;
    unsigned char* video_buf = (unsigned char*)VIDEO_BUF_PTR;
    video_buf += 80 * 2 * cur_line;
    while (*ptr)
    {
        video_buf[0] = (unsigned char)*ptr;
        video_buf[1] = cur_color;
        video_buf += 2;
        ptr++;
    }
    cur_line++;
    if (cur_line >= 24)
        clear_scr();
    cursor_moveto();
}

void cursor_moveto()
{
    unsigned short new_pos = (cur_line * VIDEO_WIDTH) + cur_col;
    outb(CURSOR_PORT, 0x0F);
    outb(CURSOR_PORT + 1, (unsigned char)(new_pos & 0xFF));
    outb(CURSOR_PORT, 0x0E);
    outb(CURSOR_PORT + 1, (unsigned char)((new_pos >> 8) & 0xFF));
}

void next_line()
{
    cur_col = 0;
    cur_line++;
    cursor_moveto();
}

void clear_scr()
{
    unsigned char* video = (unsigned char*)VIDEO_BUF_PTR;
    int count = 0;
    while (count < VIDEO_HEIGHT * VIDEO_WIDTH)
    {
        video[0] = ' ';
        video[1] = cur_color;
        video += 2;
        count++;
    }
    cur_col = 0;
    cur_line = 0;
    cursor_moveto();
}

extern "C" int kmain()
{
    clear_scr();
    out_str("Welcome to InfoOS!");
    intr_init();
    intr_start();
    intr_enable();
    keyb_init();
    while (1)
    {
        __asm hlt;
    }
    return 0;
}