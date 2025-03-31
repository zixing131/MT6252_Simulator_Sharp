using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UnicornEngine;
using UnicornEngine.Const;


namespace MT6252_Simulator_Sharp.MtkSimalator
{
    public class MtkSimalator
    {
        // Input events
        public const int MR_MOUSE_DOWN = 1;
        public const int MR_MOUSE_UP = 2;
        public const int MR_MOUSE_MOVE = 3;
        public const int MR_KEY_PRESS = 4;
        public const int MR_KEY_RELEASE = 5;

        // Base addresses
        public const uint CONFIG_base = 0x81000000;
        public const uint DRVPDN_CON0 = CONFIG_base + 0x0320;
        public const uint DRVPDN_CON1 = CONFIG_base + 0x0324;
        public const uint DRVPDN_CON2 = CONFIG_base + 0x0328;
        public const uint DRVPDN_CON3 = CONFIG_base + 0x032c;

        // Nucleus OS definitions
        public const int NU_DRIVER_SUSPEND = 10; // Device suspend
        public const int NU_EVENT_SUSPEND = 7;   // Event suspend
        public const int NU_FINISHED = 11;       // Finished
        public const int NU_MAILBOX_SUSPEND = 3;
        public const int NU_MEMORY_SUSPEND = 9;
        public const int NU_PARTITION_SUSPEND = 8;
        public const int NU_PIPE_SUSPEND = 5;
        public const int NU_PURE_SUSPEND = 1;  // Suspend
        public const int NU_QUEUE_SUSPEND = 4; // Request suspend
        public const int NU_READY = 0;
        public const int NU_SEMAPHORE_SUSPEND = 6; // Semaphore suspend
        public const int NU_SLEEP_SUSPEND = 2;     // Sleep suspend
        public const int NU_TERMINATED = 12;

        // Screen dimensions
        public const int SCREEN_WIDTH = 240;
        public const int SCREEN_HEIGHT = 320;

        // Flash interface
        public const int SFI_TRIG = 1;   // Trigger command
        public const int SFI_MAC_EN = 2; // Memory Access Control
        public const int SFI_WIP = 4;    // Indicates writing in progress
        public const int SFI_EN = 8;     // Enable

        public const uint RW_SFI_MAC_CTL = 0x810a0000;
        public const uint RW_SFI_GPRAM_DATA_REG = 0x810a0800; // Data register to send
        public const uint RW_SFI_GPRAM_BUSY_REG = 0x83010a28; // Flash busy register
        public const uint RW_SFI_OUTPUT_LEN_REG = 0x810a0004; // Bytes to write to Flash
        public const uint RW_SFI_INPUT_LEN_REG = 0x810a0008;  // Bytes to read from Flash

        // SD card registers
        public const uint SD_ARG_REG = 0x810e0028;       // SD parameter register
        public const uint SD_CMD_REG = 0x810e0024;       // SD command register
        public const uint SD_DATA_STAT_REG = 0x810e002c; // SD data status register
        public const uint SD_CMD_STAT_REG = 0x810e0040;  // SD command status register

        public const uint SD_DATA_RESP_REG0 = 0x810e0030; // SD data response register r0
        public const uint SD_DATA_RESP_REG1 = 0x810e0034; // SD data response register r1
        public const uint SD_DATA_RESP_REG2 = 0x810e0038; // SD data response register r2
        public const uint SD_DATA_RESP_REG3 = 0x810e003c; // SD data response register r3

        public const uint SD_CMD_RESP_REG0 = 0x810e0000; // SDC command response register r0
        public const uint SD_CMD_RESP_REG1 = 0x810e0004; // SDC command response register r1
        public const uint SD_CMD_RESP_REG2 = 0x810e0008; // SDC command response register r2
        public const uint SD_CMD_RESP_REG3 = 0x810e000c; // SDC command response register r3

        public const uint SDC_DATSTA_REG = 0x810E0044; // MSDC data status register
        public const uint MSDC_CFG_REG = 0x810E0000;   // MSDC command register?
        public const uint MSDC_STA_REG = 0x810E0004;    // MSDC command status register
        public const uint MSDC_DAT_REG = 0x810E000C;    // MSDC data register
        public const uint EINT_MASK_CLR_REG = 0x81010108; // External interrupt mask register

        public const uint SystemTickReg = 0x82000230;

        // Color conversion macros
        public static byte PIXEL565R(uint v)
        {
            return (byte)(((v >> 11) << 3) & 0xff); // 5-bit red
        }

        public static byte PIXEL565G(uint v) => (byte)(((v >> 5) << 2) & 0xff);  // 6-bit green
        public static byte PIXEL565B(uint v) => (byte)((v << 3) & 0xff);           // 5-bit blue

        // Flash addresses
        public const uint FLASH_BASE_ADDR = 0x8800000;
        public const uint NOR_FLASH_BASE_ADDRESS = 0x760000;

        // DMA registers
        public const uint DMA_GLBSTA = 0x81020000;
        public const uint TMDA_BASE = 0x82000000;

        public const uint DMA_MSDC_CHANNEL = 0x200;
        public const uint DMA_SIM1_CHANNEL = 0x300;
        public const uint DMA_SIM2_CHANNEL = 0x400;

        public static uint DMA_MSDC_DATA_ADDR_REG => 0x8102002C + DMA_MSDC_CHANNEL;
        public static uint DMA_MSDC_TRANSFER_COUNT_REG => 0x81020010 + DMA_MSDC_CHANNEL;
        public static uint DMA_MSDC_CONTROL_REG => 0x81020014 + DMA_MSDC_CHANNEL;
        public static uint DMA_MSDC_START_REG => 0x81020018 + DMA_MSDC_CHANNEL;
        public static uint DMA_MSDC_INTSTA_REG => 0x8102001C + DMA_MSDC_CHANNEL;

        public static uint DMA_SIM1_DATA_ADDR_REG => 0x8102002C + DMA_SIM1_CHANNEL;
        public static uint DMA_SIM1_TRANSFER_COUNT_REG => 0x81020010 + DMA_SIM1_CHANNEL;
        public static uint DMA_SIM1_CONTROL_REG => 0x81020014 + DMA_SIM1_CHANNEL;
        public static uint DMA_SIM1_START_REG => 0x81020018 + DMA_SIM1_CHANNEL;
        public static uint DMA_SIM1_INTSTA_REG => 0x8102001C + DMA_SIM1_CHANNEL;

        public static uint DMA_SIM2_DATA_ADDR_REG => 0x8102002C + DMA_SIM2_CHANNEL;
        public static uint DMA_SIM2_TRANSFER_COUNT_REG => 0x81020010 + DMA_SIM2_CHANNEL;
        public static uint DMA_SIM2_CONTROL_REG => 0x81020014 + DMA_SIM2_CHANNEL;
        public static uint DMA_SIM2_START_REG => 0x81020018 + DMA_SIM2_CHANNEL;
        public static uint DMA_SIM2_INTSTA_REG => 0x8102001C + DMA_SIM2_CHANNEL;

        public const uint DMA_FFPG_Count_REG = 0x81020d10; // & 1 means FIFO is full
        public const uint DMA_FFPG_ADDR_REG = 0x81020d2c;  // & 1 0 means FIFO is full, 1 means not full
        public const uint DMA_FFCNT_REG = 0x81020d38;      // Can be interpreted as available FIFO bytes
        public const uint DMA_FFSIZE_REG = 0x81020d44;     // Can be interpreted as total FIFO bytes
        public const uint DMA_FFSTAT_REG = 0x81020d3c;     // & 1 means FIFO is full

        // Timer
        public const uint GPTIMER1_CON = 0x81060000;

        // SD card commands
        public const ushort SDC_CMD_CMD0 = 0x0000;
        public const ushort SDC_CMD_CMD1 = 0x0181;
        public const ushort SDC_CMD_CMD2 = 0x0502;
        public const ushort SDC_CMD_CMD3_SD = 0x0303;
        public const ushort SDC_CMD_CMD3_MMC = 0x0083;
        public const ushort SDC_CMD_CMD4 = 0x0004;
        public const ushort SDC_CMD_CMD7 = 0x0387;
        public const ushort SDC_CMD_CMD8 = 0x0088;
        public const ushort SDC_CMD_CMD9 = 0x0109;
        public const ushort SDC_CMD_CMD10 = 0x010a;
        public const ushort SDC_CMD_CMD11_MMC = 0x188b;
        public const ushort SDC_CMD_CMD12 = 0x438c;
        public const ushort SDC_CMD_CMD13 = 0x008d;
        public const ushort SDC_CMD_CMD15 = 0x000f;
        public const ushort SDC_CMD_CMD16 = 0x0090;
        public const ushort SDC_CMD_CMD17 = 0x0891;
        public const ushort SDC_CMD_CMD18 = 0x1092;
        public const ushort SDC_CMD_CMD20_MMC = 0x3894;

        public const ushort SDC_CMD_CMD24 = 0x2898;
        public const ushort SDC_CMD_CMD25 = 0x3099;
        public const ushort SDC_CMD_CMD26 = 0x009a;
        public const ushort SDC_CMD_CMD27 = 0x009b;
        public const ushort SDC_CMD_CMD28 = 0x039c;
        public const ushort SDC_CMD_CMD29 = 0x039d;
        public const ushort SDC_CMD_CMD30 = 0x089e;
        public const ushort SDC_CMD_CMD32 = 0x00a0;
        public const ushort SDC_CMD_CMD33 = 0x00a1;
        public const ushort SDC_CMD_CMD34_MMC = 0x00a2;
        public const ushort SDC_CMD_CMD35_MMC = 0x00a3;
        public const ushort SDC_CMD_CMD36_MMC = 0x00a4;
        public const ushort SDC_CMD_CMD37_MMC = 0x00a5;
        public const ushort SDC_CMD_CMD38 = 0x03a6;
        public const ushort SDC_CMD_CMD39_MMC = 0x0227;
        public const ushort SDC_CMD_CMD40_MMC = 0x82a8;
        public const ushort SDC_CMD_CMD41_SD = 0x01a9;
        public const ushort SDC_CMD_CMD42 = 0x2baa;
        public const ushort SDC_CMD_CMD55 = 0x00b7;
        public const ushort SDC_CMD_CMD56 = 0x00b8;
        public const ushort SDC_CMD_ACMD6 = 0x0086;
        public const ushort SDC_CMD_ACMD13 = 0x088d;
        public const ushort SDC_CMD_ACMD22 = 0x0896;
        public const ushort SDC_CMD_ACMD23 = 0x0097;
        public const ushort SDC_CMD_ACMD42 = 0x00aa;
        public const ushort SDC_CMD_ACMD51 = 0x08b3;

        // Error codes
        public const int RTF_NO_ERROR = 0;
        public const int RTF_ERROR_RESERVED = -1;
        public const int RTF_PARAM_ERROR = -2;
        public const int RTF_INVALID_FILENAME = -3;
        public const int RTF_DRIVE_NOT_FOUND = -4;
        public const int RTF_TOO_MANY_FILES = -5;
        public const int RTF_NO_MORE_FILES = -6;
        public const int RTF_WRONG_MEDIA = -7;
        public const int RTF_INVALID_FILE_SYSTEM = -8;
        public const int RTF_FILE_NOT_FOUND = -9;
        public const int RTF_INVALID_FILE_HANDLE = -10;
        public const int RTF_UNSUPPORTED_DEVICE = -11;
        public const int RTF_UNSUPPORTED_DRIVER_FUNCTION = -12;
        public const int RTF_CORRUPTED_PARTITION_TABLE = -13;
        public const int RTF_TOO_MANY_DRIVES = -14;
        public const int RTF_INVALID_FILE_POS = -15;
        public const int RTF_ACCESS_DENIED = -16;
        public const int RTF_STRING_BUFFER_TOO_SMALL = -17;
        public const int RTF_GENERAL_FAILURE = -18;
        public const int RTF_PATH_NOT_FOUND = -19;
        public const int RTF_FAT_ALLOC_ERROR = -20;
        public const int RTF_ROOT_DIR_FULL = -21;
        public const int RTF_DISK_FULL = -22;
        public const int RTF_TIMEOUT = -23;
        public const int RTF_BAD_SECTOR = -24;
        public const int RTF_DATA_ERROR = -25;
        public const int RTF_MEDIA_CHANGED = -26;
        public const int RTF_SECTOR_NOT_FOUND = -27;
        public const int RTF_ADDRESS_MARK_NOT_FOUND = -28;
        public const int RTF_DRIVE_NOT_READY = -29;
        public const int RTF_WRITE_PROTECTION = -30;
        public const int RTF_DMA_OVERRUN = -31;
        public const int RTF_CRC_ERROR = -32;
        public const int RTF_DEVICE_RESOURCE_ERROR = -33;
        public const int RTF_INVALID_SECTOR_SIZE = -34;
        public const int RTF_OUT_OF_BUFFERS = -35;
        public const int RTF_FILE_EXISTS = -36;
        public const int RTF_LONG_FILE_POS = -37;
        public const int RTF_FILE_TOO_LARGE = -38;
        public const int RTF_BAD_DIR_ENTRY = -39;
        public const int RTF_ATTR_CONFLICT = -40;            // Recoverable support: Can't specify FS_PROTECTION_MODE and FS_NONBLOCK_MODE
        public const int RTF_CHECKDISK_RETRY = -41;          // Recoverable support: used for CROSSLINK
        public const int RTF_LACK_OF_PROTECTION_SPACE = -42; // UN-USED

        // Interrupt registers
        public const uint IRQ_SEL0 = 0x81010000;       // Interrupt selection register
        public const uint IRQ_MASK_STA_L = 0x81010070; // Interrupt mask register
        public const uint IRQ_MASK_STA_H = 0x81010074; // Interrupt mask register
        public const uint IRQ_Status = 0x810100d8;     // Interrupt status register

        public const uint RTC_IRQ_STATUS = 0x810B0004;

        public const uint IRQ_EOI2 = 0x810100dc;
        public const uint IRQ_EOIL = 0x810100a0; // Interrupt completion register
        public const uint IRQ_EOIH = 0x810100a4; // Interrupt completion register

        public const uint FIQ_FEOI = 0x810100D4; // Interrupt completion register
        public const uint IRQ_CLR_MASK_L = 0x81010080;
        public const uint IRQ_CLR_MASK_H = 0x81010084;
        public const uint IRQ_MASK_SET_L = 0x81010090;
        public const uint IRQ_MASK_SET_H = 0x81010094;
        public const uint RTC_IRQ_STATUS_REG = 0x810b0004;

        // Thread control
        public const uint TCD_Current_Thread = 0x4000b238;

        // UART registers
        public const uint UART1_RX_Buffer = 0x81030000;
        public const uint UART2_RX_Buffer = 0x81040000;
        public const uint UART3_RX_Buffer = 0x81050000;

        public const uint UART_Interrupt_Identification_REG = 0x81030008;
        public const uint UART_LINE_STATUS_REG = 0x81030014;

        public static uint UART_RX_REG(int n) => (uint)(0x78000000 + 0x100 * (n - 1));
        public static uint UART_TX_REG(int n) => (uint)(0x78000300 + 0x100 * (n - 1));

        public const uint IRQ_HANDLER = 0x4000A290; // Interrupt entry address
        public const uint IRQ_TABLE = 0x4000C840;   // Interrupt function table address

        // SIM card registers
        public const uint SIM1_BASE = 0x81090000;
        public const uint SIM1_IRQ_ENABLE = 0x81090010;
        public const uint SIM1_IRQ_STATUS = 0x81090014; // SIM_INS
        public const uint SIM1_TIDE = 0x81090024;       // Low 8 bits all 0 means RX_IDE, second byte low 8 bits all 0 means TX_IDE
        public const uint SIM1_DATA = 0x81090030;
        public const uint SIM1_COUNT = 0x81090034;
        public const uint SIM1_TOUT = 0x81090048;
        public const uint SIM1_INS_REG = 0x81090060;
        public const uint SIM1_SW1_REG = 0x81090068;
        public const uint SIM1_SW2_REG = 0x8109006C;
        public const uint SIM1_CARD_TYPE_REG = 0x81090070;
        public const uint SIM1_STATUS_REG = 0x81090074;

        public const uint SIM2_BASE = 0x810f0000;
        public const uint SIM2_IRQ_ENABLE = 0x810f0010;
        public const uint SIM2_IRQ_STATUS = 0x810f0014; // SIM_INS
        public const uint SIM2_TIDE = 0x810f0024;       // Low 8 bits all 0 means RX_IDE, second byte low 8 bits all 0 means TX_IDE
        public const uint SIM2_DATA = 0x810f0030;
        public const uint SIM2_COUNT = 0x810f0034;
        public const uint SIM2_TOUT = 0x810f0048;
        public const uint SIM2_INS_REG = 0x810f0060;
        public const uint SIM2_SW1_REG = 0x810f0068;
        public const uint SIM2_SW2_REG = 0x810f006C;
        public const uint SIM2_CARD_TYPE_REG = 0x810f0070;
        public const uint SIM2_STATUS_REG = 0x810f0074;

        const int lcdUpdateFlag = 0;
        const int size_32mb = 1024 * 1024 * 32;
        const int size_16mb = 1024 * 1024 * 16;
        const int size_8mb = 1024 * 1024 * 8;
        const int size_4mb = 1024 * 1024 * 4;
        const int size_1mb = 1024 * 1024;
        const int size_2kb = 1024 * 2;

        const int UC_PROT_NONE = 0;
        const int UC_PROT_READ = 1;
        const int UC_PROT_WRITE = 2;
        const int UC_PROT_EXEC = 4;
        const int UC_PROT_ALL = 7;

        const int UC_ARCH_ARM = 1;
        const int UC_MODE_ARM = 0;
         

        // CPU中断服务地址
        const long CPU_ISR_CB_ADDRESS = 0x50000000;
         

        static IntPtr ROM_MEMPOOL;

        static IntPtr RAM_MEMPOOL;

        static IntPtr RAM40_POOL;

        static IntPtr RAMF0_POOL;

        static IntPtr ArrToPtr(byte[] array)
        {
            return System.Runtime.InteropServices.Marshal.UnsafeAddrOfPinnedArrayElement(array, 0); 
        }

        public static IntPtr malloc(int size)
        {
            return ArrToPtr(new byte[size]);
        }

        static Unicorn MTK;

        public static void uc_mem_map_ptr(Unicorn mtk, long address, int size, int perms, IntPtr ptr)
        {
            mtk.MemMapPtr(address, size, perms, ptr);
        }

        public static VM_SIM_DEV vm_sim1_dev = new VM_SIM_DEV(true);
        public static VM_SIM_DEV vm_sim2_dev = new VM_SIM_DEV(true); 

        public static VM_DMA_CONFIG vm_dma_msdc_config = new VM_DMA_CONFIG(true);
        public static VM_DMA_CONFIG vm_dma_sim1_config = new VM_DMA_CONFIG(true);
        public static VM_DMA_CONFIG vm_dma_sim2_config = new VM_DMA_CONFIG(true);


        /// <summary>
        /// 初始化模拟CPU引擎与内存
        /// </summary>
        public static void initMtkSimalator()
        {
            //初始MTK引擎
            MTK = new Unicorn(UC_ARCH_ARM, UC_MODE_ARM);

            ROM_MEMPOOL = malloc(size_16mb);
            RAM_MEMPOOL = malloc(size_8mb);
            // 映射寄存器
            uc_mem_map_ptr(MTK, 0x80000000, size_8mb, UC_PROT_ALL, malloc(size_8mb));

            // GPIO_BASE_ADDRESS
            uc_mem_map_ptr(MTK, 0x81000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, TMDA_BASE, size_4mb, UC_PROT_ALL, malloc(size_4mb));
            uc_mem_map_ptr(MTK, 0x83000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x84000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x85000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));


            // 未知 分区
            uc_mem_map_ptr(MTK, 0x70000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x78000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x90000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0xA0000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0xA1000000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0xA2000000, size_4mb, UC_PROT_ALL, malloc(size_4mb));
            uc_mem_map_ptr(MTK, 0xA3000000, size_4mb, UC_PROT_ALL, malloc(size_4mb));


            // err = uc_mem_map_ptr(MTK, 0xE5900000, size_4mb, UC_PROT_ALL, malloc(size_4mb));
            RAMF0_POOL = malloc(size_8mb);
            uc_mem_map_ptr(MTK, 0xF0000000, size_8mb, UC_PROT_ALL, RAMF0_POOL);
            uc_mem_map_ptr(MTK, 0x01FFF000, size_1mb, UC_PROT_ALL, malloc(size_1mb));
            // 映射ROM
            uc_mem_map_ptr(MTK, 0x08000000, size_16mb, UC_PROT_ALL, ROM_MEMPOOL);
            // 中断栈
            uc_mem_map_ptr(MTK, CPU_ISR_CB_ADDRESS, size_1mb, UC_PROT_ALL, malloc(size_1mb));


            // 映射RAM
            uc_mem_map_ptr(MTK, 0, size_8mb, UC_PROT_ALL, RAM_MEMPOOL);

            // 映射外部INIT_SRAM
            RAM40_POOL = malloc(size_8mb);
            uc_mem_map_ptr(MTK, 0x40000000, size_8mb, UC_PROT_ALL, RAM40_POOL);
            // hook kal_fatal_error_handler
            // err = uc_hook_add(uc, &trace, UC_HOOK_CODE, hookCodeCallBack, 0, 0, 0xFFFFFFFF);
            // 中断
            MTK.AddBlockHook(hookBlockCallBack, 4, CPU_ISR_CB_ADDRESS, CPU_ISR_CB_ADDRESS + 4);
            // 回调
            MTK.AddBlockHook(hookBlockCallBack,  5, CPU_ISR_CB_ADDRESS + 8, CPU_ISR_CB_ADDRESS + 12);

            MTK.AddBlockHook(hookBlockCallBack, 7, 0x4000801E, 0x4000801F);

            MTK.AddBlockHook(hookBlockCallBack, 8, 0, 0xffffffff);

            MTK.AddCodeHook(hookCodeCallBack, 0, 0x08000000, 0x09000000);

            MTK.AddMemReadHook(hookRamCallBack, 0, 0x80000000, 0xA2000000);

            MTK.AddMemReadHook(hookRamCallBack, 0, 0x5f288, 0x5f888);

            MTK.AddMemWriteHook(hookRamCallBack, 1, 0x78000000, 0x78f00000);

            MTK.AddMemWriteHook(hookRamCallBack, 1, 0x80000000, 0x81ffffff);

            MTK.AddMemWriteHook(hookRamCallBack, 1, 0x90000000, 0x91000000);
            MTK.AddMemWriteHook(hookRamCallBack, 1, 0xf0000000, 0xf2000000);

        }

        private static void hookRamCallBack(Unicorn P_0, long address, int size, long value, object userData)
        {

        }

        private static void hookRamCallBack(Unicorn uc, long address, int size, object userData)
        {

        }
        private static void hookCodeCallBack(Unicorn uc, long address, int size, object userData)
        {
            long changeTmp1 = 0;
            long changeTmp = 0;
            byte changeTmp2 = 0;
            byte[] globalSprintfBuff = new byte[128];
            long lastSIM_DMA_ADDR = 0;
            long lastAddress = 0;

            switch (address)
            {
                case 0x8370220: // 直接返回开机流程任务全部完成
                    changeTmp1 = 1;
                    uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp1);
                    break;

                case 0x81b38d0:
                    changeTmp1 = uc.RegRead(Arm.UC_ARM_REG_R1);
                    Console.WriteLine($"l1audio_sethandler({changeTmp1:X})");
                    break;

                case 0x8087256:
                    changeTmp1 = uc.RegRead(Arm.UC_ARM_REG_R0);
                    Console.WriteLine($"sim_check_status v26({changeTmp1:X})");
                    break;

                case 0x80D2EE0:
                    changeTmp1 = uc.RegRead(Arm.UC_ARM_REG_R2);
                    lastSIM_DMA_ADDR = changeTmp1;
                    Console.WriteLine($"SIM_CMD(r0,r1,rx_result:{changeTmp1:X})");
                    break;

                case 0x819f5b4:
                    changeTmp1 = uc.RegRead(Arm.UC_ARM_REG_R0);
                    uc.MemRead(changeTmp1, globalSprintfBuff);
                    Console.WriteLine($"kal_debug_print({System.Text.Encoding.ASCII.GetString(globalSprintfBuff)})({lastAddress:X})");
                    break;

                case 0x82D2A22: // mr_sprintf
                    uc.MemRead(0xF028EDC4, globalSprintfBuff);
                    Console.WriteLine($"mr_sprintf({System.Text.Encoding.ASCII.GetString(globalSprintfBuff)})");
                    break;

                case 0x81a4d54:
                    changeTmp1 = uc.RegRead(Arm.UC_ARM_REG_R0);
                    uc.MemRead(changeTmp1, globalSprintfBuff);
                    Console.WriteLine($"dbg_print({System.Text.Encoding.ASCII.GetString(globalSprintfBuff)})[{lastAddress:X}]");
                    break;

                case 0x83D1C28: // mr_mem_get()
                    changeTmp1 = 0;
                    uc.MemWrite(0xF0166068, BitConverter.GetBytes(changeTmp1));
                    break;

                case 0x83890C8:
                    // srv_charbat_get_charger_status默认返回1，是充电状态
                    changeTmp1 = 1;
                    uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp1);
                    break;

                case 0x80E7482:
                    // 强制过 nvram_util_caculate_checksum检测
                    changeTmp = uc.RegRead(Arm.UC_ARM_REG_R0);
                    changeTmp1 = uc.RegRead(Arm.UC_ARM_REG_R2);
                    uc.RegWrite(Arm.UC_ARM_REG_R2, changeTmp);
                    break;

                case 0x8093FB2: // 强制过8093ffa方法
                    changeTmp = 1;
                    uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp);
                    break;

                case 0x80D2CA4:
                    // 过sub_80D2CA4
                    changeTmp = uc.RegRead(Arm.UC_ARM_REG_R5);
                    changeTmp2 = 0xff;
                    uc.MemWrite(changeTmp + 3, new byte[] { changeTmp2 });
                    break;

                case 0x80601ec:
                case 0x80601ac: // 过sub_8060194的while(L1D_WIN_Init_SetCommonEvent)
                    changeTmp = uc.RegRead(Arm.UC_ARM_REG_R0);
                    uc.MemWrite(TMDA_BASE, BitConverter.GetBytes(changeTmp));
                    break;

                case 0x8223F66: // 过sub_8223f5c(L1层的)
                    changeTmp = 0;
                    uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp);
                    break;

                case 0x800DA28: // 暂时去不掉
                    changeTmp = 0;
                    uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp);
                    break;

                default:
                    break;
            }

            lastAddress = address;
        }



        private static void hookBlockCallBack(Unicorn uc, long address, int size, object user_data)
        {
            VmEvent vmEvent;
            switch ((uint)user_data)
            {
                case 4: // 中断恢复
                    RestoreCpuContext(isrStackList.Pop());
                    irq_nested_count--;
                    break;
                case 5: // 回调恢复
                    RestoreCpuContext(stackCallback);
                    break;
                case 7:
                    // 过方法sub_87035D4 (0x4000801E)
                    changeTmp = 1;
                    MTK.RegWrite( Arm.UC_ARM_REG_R0, changeTmp);

                    break;
                case 8: // 各种事件处理
                    if (VmEventPtr > 0)
                    {
                        vmEvent = DequeueVMEvent();
                        if (vmEvent != null)
                        {
                            switch (vmEvent.Event)
                            {
                                case VM_EVENT.VM_EVENT_KEYBOARD:
                                    // 按键中断
                                    if (StartInterrupt(8, address))
                                        SimulatePressKey(vmEvent.R0, vmEvent.R1);
                                    else // 如果处理失败，重新入队
                                        EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                    break;
                                case VM_EVENT.VM_EVENT_SIM_IRQ:
                                    // 进入usim中断
                                    changeTmp1 = (int)vmEvent.R0;
                                    if (vmEvent.R1 == 0)
                                    {
                                        UcMemWrite(uc, SIM1_IRQ_STATUS, ref changeTmp1, 4); // 卡一
                                        if (!StartInterrupt(5, address))
                                        {
                                            EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                        }
                                    }
                                    if (vmEvent.R1 == 1)
                                    {
                                        UcMemWrite(uc, SIM2_IRQ_STATUS, ref changeTmp1, 4); // 卡二
                                        if (!StartInterrupt(28, address))
                                        {
                                            EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                        }
                                    }
                                    break;
                                case VM_EVENT.VM_EVENT_SIM_T0_TX_END:
                                    if (vmEvent.R0 == 0)
                                    {
                                        HandleSimTxCmd(ref vm_sim1_dev, vmEvent.R0, vm_dma_sim1_config.TransferCount, vm_dma_sim1_config.DataAddr);
                                    }
                                    else if (vmEvent.R0 == 1)
                                    {
                                        HandleSimTxCmd(ref vm_sim2_dev, vmEvent.R0, vm_dma_sim2_config.TransferCount, vm_dma_sim2_config.DataAddr);
                                    }
                                    break;
                                case VM_EVENT.VM_EVENT_SIM_T0_RX_END:
                                    if (vmEvent.R0 == 0)
                                    {
                                        HandleSimRxCmd(ref vm_sim1_dev, vmEvent.R0, vm_dma_sim1_config.TransferCount, vm_dma_sim1_config.DataAddr);
                                    }
                                    else if (vmEvent.R0 == 1)
                                    {
                                        HandleSimRxCmd(ref vm_sim2_dev, vmEvent.R0, vm_dma_sim2_config.TransferCount, vm_dma_sim2_config.DataAddr);
                                    }
                                    break;
                                case VM_EVENT.VM_EVENT_DMA_IRQ:
                                    if (!StartInterrupt(6, address))
                                    {
                                        EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                    }
                                    break;
                                case VM_EVENT.VM_EVENT_MSDC_IRQ:
                                    /*
                                    // todo 进入中断可以过多数据块读写的等待响应，但结果不正确
                                    changeTmp1 = 2;
                                    UcMemWrite(uc, 0x810e0008, ref changeTmp1, 4);
                                    changeTmp1 = 0;
                                    UcMemWrite(uc, 0x810e0010, ref changeTmp1, 4);
                                    if (!StartInterrupt(0xd, address))
                                    {
                                        EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                    }*/
                                    break;
                                case VM_EVENT.VM_EVENT_GPT_IRQ:
                                    // GPT中断
                                    StartInterrupt(10, address);
                                    break;
                                case VM_EVENT.VM_EVENT_RTC_IRQ:
                                    UpdateRtcTime();
                                    StartInterrupt(14, address);
                                    break;
                                case VM_EVENT.VM_EVENT_Timer_IRQ:
                                    // 定时中断2号中断线
                                    StartInterrupt(2, address);
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                    break;
            }
        }

        private static void RestoreCpuContext(CpuContext context)
        {
            // 恢复CPU上下文
        }

        private static void UcRegWrite(Unicorn uc, VM_EVENT reg, ref int value)
        {
            // 写入寄存器
        }

        private static void UcMemWrite(Unicorn uc, ulong address, ref int value, int size)
        {
            // 写入内存
        }

        private static bool StartInterrupt(int irq, long address)
        {
            // 启动中断
            return true;
        }

        private static void SimulatePressKey(uint r0, uint r1)
        {
            // 模拟按键
        }

        private static VmEvent DequeueVMEvent()
        {
            // 出队事件
            return vmEventQueue.Dequeue();
        }

        private static void EnqueueVMEvent(VM_EVENT eventType, uint r0, uint r1)
        {
            // 入队事件
            vmEventQueue.Enqueue(new VmEvent { Event = eventType, R0 = r0, R1 = r1 });
        }

        private static void HandleSimTxCmd(ref VM_SIM_DEV simDev, uint r0, uint transferCount, ulong dataAddr)
        {
            // 处理SIM TX命令
        }

        private static void HandleSimRxCmd(ref VM_SIM_DEV simDev, uint r0, uint transferCount, ulong dataAddr)
        {
            // 处理SIM RX命令
        }

        private static void UpdateRtcTime()
        {
            // 更新RTC时间
        }

        private static int irq_nested_count = 0;
        private static Stack<CpuContext> isrStackList = new Stack<CpuContext>();
        private static CpuContext stackCallback = new CpuContext();
        private static int changeTmp = 0;
        private static int changeTmp1 = 0;
        private static int VmEventPtr = 0;
        private static Queue<VmEvent> vmEventQueue = new Queue<VmEvent>();

    }
}
