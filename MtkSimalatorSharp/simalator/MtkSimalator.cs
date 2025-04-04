using MtkSimalatorSharp.backend;
using System;
using System.Drawing;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Text; 


namespace MT6252_Simulator_Sharp.Simalator
{
    //https://github.com/unicorn-engine/unicorn/releases/download/1.0.2/unicorn-1.0.2-win32.zip
    public class MtkSimalator
    {
        // 定时中断配置，单位毫秒
        public const int Timer_Interrupt_Duration = 1000;

        // SD卡镜像文件配置
        //public const string SD_CARD_IMG_PATH = @"Rom\fat32.img";
        public const string SD_CARD_IMG_PATH = @"Rom\fat32.img";

        // Rom Flash文件配置 
        public const string FLASH_IMG_PATH = @"Rom\\flash.img";

        // Rom Flash lock配置
        public const string FLASH_IMG_LOCK_PATH = @"Rom\flash.lock";

        // 系统固件文件
        //public const string ROM_PROGRAM_BIN = @"Rom\08000000.bin";

        // 系统固件文件
        public const string ROM_PROGRAM_BIN = @"Rom\08000000.bin";

        // LCD屏幕宽度
        public const int LCD_SCREEN_WIDTH = 240;

        // LCD屏幕高度  
        public const int LCD_SCREEN_HEIGHT = 320;

        // CPU中断服务地址
        public const uint CPU_ISR_CB_ADDRESS = 0x50000000;

        // 中断间隔
        public const int interruptPeroidms = 5;
        

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

        // Flash addresses
        public const uint FLASH_BASE_ADDR = 0x8800000;
        public const uint NOR_FLASH_BASE_ADDRESS = 0x760000;

        // DMA registers
        public const uint DMA_GLBSTA = 0x81020000;
        public const uint TMDA_BASE = 0x82000000;

        public const uint DMA_MSDC_CHANNEL = 0x200;
        public const uint DMA_SIM1_CHANNEL = 0x300;
        public const uint DMA_SIM2_CHANNEL = 0x400;

        public const uint DMA_MSDC_DATA_ADDR_REG = 0x8102002C + DMA_MSDC_CHANNEL;
        public const uint DMA_MSDC_TRANSFER_COUNT_REG = 0x81020010 + DMA_MSDC_CHANNEL;

        public const uint DMA_MSDC_CONTROL_REG = 0x81020014 + DMA_MSDC_CHANNEL;
        public const uint DMA_MSDC_START_REG =0x81020018 + DMA_MSDC_CHANNEL;
        public const uint DMA_MSDC_INTSTA_REG =0x8102001C + DMA_MSDC_CHANNEL;

        public const uint DMA_SIM1_DATA_ADDR_REG = 0x8102002C + DMA_SIM1_CHANNEL;
        public const uint DMA_SIM1_TRANSFER_COUNT_REG = 0x81020010 + DMA_SIM1_CHANNEL;
        public const uint DMA_SIM1_CONTROL_REG = 0x81020014 + DMA_SIM1_CHANNEL;
        public const uint DMA_SIM1_START_REG =0x81020018 + DMA_SIM1_CHANNEL;
        public const uint DMA_SIM1_INTSTA_REG =0x8102001C + DMA_SIM1_CHANNEL;

        public const uint DMA_SIM2_DATA_ADDR_REG =0x8102002C + DMA_SIM2_CHANNEL;
        public const uint DMA_SIM2_TRANSFER_COUNT_REG =0x81020010 + DMA_SIM2_CHANNEL;
        public const uint DMA_SIM2_CONTROL_REG = 0x81020014 + DMA_SIM2_CHANNEL;
        public const uint DMA_SIM2_START_REG =0x81020018 + DMA_SIM2_CHANNEL;
        public const uint DMA_SIM2_INTSTA_REG = 0x8102001C + DMA_SIM2_CHANNEL;

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

        static bool lcdUpdateFlag = false;
        public static uint[] LCD_Layer_Address = new uint[4];

        const int size_32mb = 1024 * 1024 * 32;
        const int size_16mb = 1024 * 1024 * 16;
        const int size_8mb = 1024 * 1024 * 8;
        const int size_4mb = 1024 * 1024 * 4;
        const int size_1mb = 1024 * 1024;
        const int size_2kb = 1024 * 2;
         
        static IntPtr ROM_MEMPOOL;

        static IntPtr RAM_MEMPOOL;

        static IntPtr RAM40_POOL;

        static IntPtr RAMF0_POOL;

        static uint MSDC_CMD_CACHE = 0;

        static uint MSDC_DATA_ADDR = 0;

        static uint IRQ_MASK_SET_L_Data = 0;


        static uint[][] isrStackList = new uint[10][] ;
        static uint[] stackCallback = new uint[17];

        //private static uint[] getRowOfArray(uint[,] array,uint rowIndexUint)
        //{
        //    int rowIndex = (int)rowIndexUint;
        //    uint[] row = new uint[17]; // 存储提取的行
        //    Buffer.BlockCopy(array, rowIndex * 17 * sizeof(uint), row, 0, 17 * sizeof(uint));
        //    return row;
        //}

        // Instance of the struct
        public static SerialFlash_Control SF_C_Frame = new SerialFlash_Control
        {
            SR_REG = new byte[3],
            cmd = 0,
            address = 0,
            cmdRev = 0,
            sendDataCount = 0,
            readDataCount = 0,
            cacheData = new uint[70]
        }; 

        //static IntPtr ArrToPtr(byte[] array)
        //{
        //    // 固定托管内存（避免 GC 移动）
        //    GCHandle handle = GCHandle.Alloc(array, GCHandleType.Pinned);
        //   // try
        //    //{
        //        IntPtr ptr = handle.AddrOfPinnedObject();
        //        // 现在 ptr 可以安全传递到非托管代码
        //        // NativeMethod(ptr, byteArray.Length);
        //        return ptr;
        //    //}
        //    //finally
        //    //{
        //    //    // 必须手动释放 GCHandle
        //    //    if (handle.IsAllocated)
        //    //        handle.Free();
        //    //}

        //    // return System.Runtime.InteropServices.Marshal.UnsafeAddrOfPinnedArrayElement(array, 0);
        //}

        public static IntPtr malloc(int size)
        {
            return IntPtr.Zero;
            // return ArrToPtr(new byte[size]);
        }

        //初始MTK引擎
        public static IBackend MTK = null;
        public static bool isSuccess()
        {
            return MTK != null;
        }
        public static void uc_mem_map_ptr(IBackend mtk, uint address, int size, int perms, IntPtr ptr)
        {
            mtk.MemMap(address, size, perms);
            //  mtk.MemMapPtr(address, size, perms, ptr);
        }

        public static VM_SIM_DEV vm_sim1_dev = new VM_SIM_DEV(true);
        public static VM_SIM_DEV vm_sim2_dev = new VM_SIM_DEV(true); 

        public static VM_DMA_CONFIG vm_dma_msdc_config = new VM_DMA_CONFIG(true);
        public static VM_DMA_CONFIG vm_dma_sim1_config = new VM_DMA_CONFIG(true);
        public static VM_DMA_CONFIG vm_dma_sim2_config = new VM_DMA_CONFIG(true);

        private static void initData()
        {
            for (int i = 0; i < 10; i++)
            {
                // 为每个 uint* 分配 17 个 uint 的空间
                isrStackList[i] = new uint[17];

                // 初始化为 0
                for (int j = 0; j < 17; j++)
                {
                    isrStackList[i][j] = 0;
                }
            }

            // 初始化为0
            for (int i = 0; i < 17; i++)
            {
                stackCallback[i] = 0;
            }
        } 
        /// <summary>
        /// 初始化模拟CPU引擎与内存
        /// </summary>
        public static void initMtkSimalator()
        {
            initData();

            MTK = new UnicornNative();
            MTK.nativeInitialize(Common.UC_ARCH_ARM, Common.UC_MODE_ARM);


            ROM_MEMPOOL = malloc(size_16mb);
            RAM_MEMPOOL = malloc(size_8mb);

            // 映射寄存器
            uc_mem_map_ptr(MTK, 0x80000000, size_8mb, Common.UC_PROT_ALL, malloc(size_8mb));

            // GPIO_BASE_ADDRESS
            uc_mem_map_ptr(MTK, 0x81000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, TMDA_BASE, size_4mb, Common.UC_PROT_ALL, malloc(size_4mb));
            uc_mem_map_ptr(MTK, 0x83000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x84000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x85000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));


            // 未知 分区
            uc_mem_map_ptr(MTK, 0x70000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x78000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0x90000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0xA0000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            uc_mem_map_ptr(MTK, 0xA1000000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));

            uc_mem_map_ptr(MTK, 0xA2000000, size_4mb, Common.UC_PROT_ALL, malloc(size_4mb));
            uc_mem_map_ptr(MTK, 0xA3000000, size_4mb, Common.UC_PROT_ALL, malloc(size_4mb));


            // err = uc_mem_map_ptr(MTK, 0xE5900000, size_4mb, UC_PROT_ALL, malloc(size_4mb));
            RAMF0_POOL = malloc(size_8mb);
            uc_mem_map_ptr(MTK, 0xF0000000, size_8mb, Common.UC_PROT_ALL, RAMF0_POOL);
            uc_mem_map_ptr(MTK, 0x01FFF000, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));
            // 映射ROM
            uc_mem_map_ptr(MTK, 0x08000000, size_16mb, Common.UC_PROT_ALL, ROM_MEMPOOL);
            // 中断栈
            uc_mem_map_ptr(MTK, CPU_ISR_CB_ADDRESS, size_1mb, Common.UC_PROT_ALL, malloc(size_1mb));


            // 映射RAM
            uc_mem_map_ptr(MTK, 0, size_8mb, Common.UC_PROT_ALL, RAM_MEMPOOL);

            // 映射外部INIT_SRAM
            RAM40_POOL = malloc(size_8mb);
            uc_mem_map_ptr(MTK, 0x40000000, size_8mb, Common.UC_PROT_ALL, RAM40_POOL);
            // hook kal_fatal_error_handler
            // err = uc_hook_add(uc, &trace, UC_HOOK_CODE, hookCodeCallBack, 0, 0, 0xFFFFFFFF);
            // 中断
            BlockCallBackClass hookBlockCallBack = new BlockCallBackClass();
            MTK.HookAddNewBlockHook(hookBlockCallBack, 4, CPU_ISR_CB_ADDRESS, CPU_ISR_CB_ADDRESS + 4); 

            MTK.HookAddNewBlockHook(hookBlockCallBack,  5, CPU_ISR_CB_ADDRESS + 8, CPU_ISR_CB_ADDRESS + 12);

            MTK.HookAddNewBlockHook(hookBlockCallBack, 7, 0x4000801E, 0x4000801F);

            MTK.HookAddNewBlockHook(hookBlockCallBack, 8, 0, 0xffffffff); 


            hookCodeCallBackClass hookCodeCallBack = new hookCodeCallBackClass();

            MTK.HookAddNewCodeHook(hookCodeCallBack, 0, 0x08000000, 0x09000000);


            ReadHookClass readhook = new ReadHookClass();

            MTK.HookAddNewReadHook(readhook, 0, 0x80000000, 0xA2000000);

            MTK.HookAddNewReadHook(readhook, 0, 0x5f288, 0x5f888);

            WriteHookClass writehook = new WriteHookClass();
            MTK.HookAddNewWriteHook(writehook, 1, 0x78000000, 0x78f00000);

            MTK.HookAddNewWriteHook(writehook, 1, 0x80000000, 0x81ffffff);

            MTK.HookAddNewWriteHook(writehook, 1, 0x90000000, 0x91000000);
            MTK.HookAddNewWriteHook(writehook, 1, 0xf0000000, 0xf2000000);

            //            uc_mem_write 810a0800
            //uc_mem_write 878009b
            //uc_mem_write 810a0800
            //uc_mem_write 810a0800
            //uc_mem_write 87980b7
            //uc_mem_write 810a0800
            //uc_mem_write 810a0800
            //uc_mem_write 878009b
            //uc_mem_write 810a0800
            //0xC0000005 error 

            //uc_mem_map_ptr(MTK, 0xC0000000, size_1mb, Common.UC_PROT_ALL, IntPtr.Zero);
            EventMemHookClass eventMemHook = new EventMemHookClass();
            MTK.HookAddNewEventMemHook(eventMemHook, Common.UC_HOOK_MEM_READ_UNMAPPED | Common.UC_HOOK_MEM_WRITE_UNMAPPED | Common.UC_HOOK_MEM_FETCH_UNMAPPED, 0);
            //MTK.AddInterruptHook(InterruptHook);
            //MTK.AddMemWriteHook();

            //MTK.AddMemReadHook();  

            if (MTK != null)
            { 
                int size = 0;
                byte[] tmp = null;

                // 读取ROM文件并写入内存
                tmp = MtkSimalator.ReadFile(MtkSimalator.ROM_PROGRAM_BIN, out size);
                MtkSimalator.uc_mem_write(MtkSimalator.MTK, 0x08000000, tmp, size);

            }
        }

        static void InterruptHook(IBackend P_0, int P_1, object P_2)
        { 
            Console.WriteLine($"异常 InterruptHook");
        }

        public class EventMemHookClass: IEventMemHook
        {
            public bool hook(IBackend backend,long address, int size, long value, object userdata)
            {
                Console.WriteLine($"异常 userdata ={userdata} address = {address:x} size={size} value={value:x}");
                return true;
            }
        }
     
       

        public class ReadHookClass: IReadHook
        {
           public void hook(IBackend backend, long address, int size, object userData)
            {
                hookRamCallBack(backend, 16, (uint)address, size, 0, userData);
            }

        }


        public class WriteHookClass : IWriteHook
        {
            public void hook(IBackend backend, long address, int size, long value, object userData)
            {

                hookRamCallBack(backend, 1, (uint)address, size, (uint)value, userData);
            }
        }

        static uint lastAddress = 0;
        static int incount = 0;
        private static void hookRamCallBack(IBackend uc, int type, uint address, int size, uint value, object userData)
        {
            //Console.WriteLine($"hookRamCallBack address = ({address:X})");
            int data = 0;
            if (userData.GetType() == typeof(UInt32))
            {
                uint tmp2 = (uint)(userData);
                data = (int)tmp2; 
            }
            else if (userData.GetType() == typeof(Int32))
            { 
                data = (int)userData;
            }
            else
            {
                Console.WriteLine($"not support: {userData}");
            } 

            // Merge images: smaller layer numbers are lower layers, larger are upper layers
            switch (address)
            {
                case SIM1_CARD_TYPE_REG:
                    changeTmp1 = 0x20;
                    uc.MemWrite(address, Uint2Bytes(changeTmp1, 1));
                    Console.WriteLine($"read sim1_card_type({lastAddress:x})");
                    break;
                case SIM2_CARD_TYPE_REG:
                    changeTmp1 = 0x20;
                    uc.MemWrite(address, Uint2Bytes(changeTmp1, 1));
                    Console.WriteLine($"read sim2_card_type({lastAddress:x})");
                    break;
                case SIM1_TIDE:
                    if (data == 1)
                        SIM_TIDE_HANDLE(ref vm_sim1_dev, 0, value);
                    break;
                case SIM2_TIDE:
                    if (data == 1)
                        SIM_TIDE_HANDLE(ref vm_sim2_dev, 1, value);
                    break;
                case SIM1_IRQ_ENABLE:
                    if (data == 1)
                        SIM_IRQ_HANDLE(ref vm_sim1_dev, 0, value);
                    break;
                case SIM2_IRQ_ENABLE:
                    if (data == 1)
                        SIM_IRQ_HANDLE(ref vm_sim2_dev, 1, value);
                    break;
                case SIM1_BASE:
                    if (data == 1)
                        SIM_BASE_HANDLE(ref vm_sim1_dev, 0, value);
                    break;
                case SIM2_BASE:
                    if (data == 1)
                        SIM_BASE_HANDLE(ref vm_sim2_dev, 1, value);
                    break;
                case SIM1_DATA:
                    SIM_DATA_HANDLE(ref vm_sim1_dev, 0, (byte) data, value);
                    break;
                case SIM2_DATA:
                    SIM_DATA_HANDLE(ref vm_sim2_dev, 1, (byte)data, value);
                    break;
                case 0x82050000: // Write 1 becomes 0
                    changeTmp = 0;
                    uc.MemWrite(address, Uint2Bytes(changeTmp));
                    break;
                case 0xa0000000:
                    changeTmp = 0x5555;
                    uc.MemWrite(address, Uint2Bytes(changeTmp));
                    break;
                case 0xA10003F6:
                    changeTmp = 0x8888;
                    uc.MemWrite(address, Uint2Bytes(changeTmp));
                    break;
                case 0x9000000c: // LCD Interface Frame Transfer Register
                    if (value == 0 && data == 1)
                    {
                        lcdUpdateFlag = true;
                    }
                    break;
                case 0x9000014c: // Layer 3 Address
                    if (data == 1)
                    {
                        LCD_Layer_Address[3] = (uint)value;
                    }
                    break;
                case 0x9000011c: // Layer 2 Address
                    if (data == 1)
                    {
                        LCD_Layer_Address[2] = (uint)value;
                    }
                    break;
                case 0x900000ec: // Layer 1 Address
                    if (data == 1)
                    {
                        LCD_Layer_Address[1] = (uint)value;
                    }
                    break;
                case 0x900000bc: // Layer 0 Address
                    if (data == 1)
                    {
                        LCD_Layer_Address[0] = (uint)value;
                    }
                    break;
                case DMA_MSDC_CONTROL_REG:
                    if (data == 1)
                    {
                        vm_dma_msdc_config.Control = (uint)value;
                        vm_dma_msdc_config.Chanel = (DMA_MASTER_CHANEL)(byte)((value >> 20) & 31);
                        vm_dma_msdc_config.Direction = (DMA_DATA_DIRECTION)(byte)((value >> 18) & 1);
                        vm_dma_msdc_config.Align = (DMA_DATA_BYTE_ALIGN)(byte)(value & 3);
                        vm_dma_msdc_config.TransferEndInterruptEnable = (byte)((value >> 15) & 1);
                    }
                    break;
                case DMA_SIM1_CONTROL_REG:
                    if (data == 1)
                    {
                        vm_dma_sim1_config.Control = (uint)value;
                        vm_dma_sim1_config.Chanel = (DMA_MASTER_CHANEL)(byte)((value >> 20) & 31);
                        vm_dma_sim1_config.Direction = (DMA_DATA_DIRECTION)(byte)((value >> 18) & 1);
                        vm_dma_sim1_config.Align = (DMA_DATA_BYTE_ALIGN)(byte)(value & 3);
                        vm_dma_sim1_config.TransferEndInterruptEnable = (byte)((value >> 15) & 1);
                    }
                    break;
                case DMA_SIM2_CONTROL_REG:
                    if (data == 1)
                    {
                        vm_dma_sim2_config.Control = (uint)value;
                        vm_dma_sim2_config.Chanel = (DMA_MASTER_CHANEL)(byte)((value >> 20) & 31);
                        vm_dma_sim2_config.Direction = (DMA_DATA_DIRECTION)(byte)((value >> 18) & 1);
                        vm_dma_sim2_config.Align = (DMA_DATA_BYTE_ALIGN)(byte)(value & 3);
                        vm_dma_sim2_config.TransferEndInterruptEnable = (byte)((value >> 15) & 1);
                    }
                    break;
                case DMA_MSDC_DATA_ADDR_REG:
                    if (data == 1)
                        vm_dma_msdc_config.DataAddr = (uint)value;
                    break;
                case DMA_SIM1_DATA_ADDR_REG:
                    if (data == 1)
                        vm_dma_sim1_config.DataAddr = (uint)value;
                    break;
                case DMA_SIM2_DATA_ADDR_REG:
                    if (data == 1)
                        vm_dma_sim2_config.DataAddr = (uint)value;
                    break;
                case DMA_MSDC_TRANSFER_COUNT_REG:
                    if (data == 1)
                    {
                        if (vm_dma_msdc_config.Align == DMA_DATA_BYTE_ALIGN.DMA_DATA_BYTE_ALIGN_FOUR)
                            value *= 4;
                        if (vm_dma_msdc_config.Align == DMA_DATA_BYTE_ALIGN.DMA_DATA_BYTE_ALIGN_TWO)
                            value *= 2;
                        vm_dma_msdc_config.TransferCount = (uint)value;
                    }
                    break;
                case DMA_SIM1_TRANSFER_COUNT_REG:
                    if (data == 1)
                    {
                        if (vm_dma_sim1_config.Align == DMA_DATA_BYTE_ALIGN.DMA_DATA_BYTE_ALIGN_FOUR)
                            value *= 4;
                        if (vm_dma_sim1_config.Align == DMA_DATA_BYTE_ALIGN.DMA_DATA_BYTE_ALIGN_TWO)
                            value *= 2;
                        vm_dma_sim1_config.TransferCount = (uint)value;
                    }
                    break;
                case DMA_SIM2_TRANSFER_COUNT_REG:
                    if (data == 1)
                    {
                        if (vm_dma_sim2_config.Align == DMA_DATA_BYTE_ALIGN.DMA_DATA_BYTE_ALIGN_FOUR)
                            value *= 4;
                        if (vm_dma_sim2_config.Align == DMA_DATA_BYTE_ALIGN.DMA_DATA_BYTE_ALIGN_TWO)
                            value *= 2;
                        vm_dma_sim2_config.TransferCount = (uint)value;
                    }
                    break;
                case DMA_MSDC_START_REG:
                    if (data == 1 && value == 0x8000)
                    {
                        if (vm_dma_msdc_config.Chanel == DMA_MASTER_CHANEL.MSDC)
                        {
                            vm_dma_msdc_config.ConfigFinish = 1;
                        }
                        else
                        {
                            Console.WriteLine($"unhandle msdc dma chanel[{vm_dma_msdc_config.Chanel:x}]");
                        }
                    }
                    break;
                case DMA_SIM1_START_REG:
                    if (data == 1)
                    {
                        if (value == 0x8000)
                        {
                            // 写入0x8000表示DMA开始运行
                            if (vm_dma_sim1_config.Chanel == 0)
                            {
                                vm_dma_sim1_config.ConfigFinish = 1;
                                Console.WriteLine($"SIM卡1的DMA开启({irq_nested_count})");
                            }
                            else
                            {
                                Console.WriteLine($"unhandle sim1 dma chanel[{vm_dma_sim1_config.Chanel:x}]");
                            }
                        }
                    }
                    break;
                case DMA_SIM2_START_REG:
                    // 写入0x8000表示DMA开始运行
                    if (data == 1 )
                    {
                        if (value == 0x8000)
                        {
                            if (vm_dma_sim2_config.Chanel == (DMA_MASTER_CHANEL)0x13)
                            {
                                Console.WriteLine("SIM卡2的DMA开启");
                                vm_dma_sim2_config.ConfigFinish = 1;
                            }
                            else
                            {
                                Console.WriteLine($"unhandle sim2 dma chanel[{vm_dma_sim2_config.Chanel:x}]");
                            }
                        }
                     
                    }
                    break;
                case 0x810C0090: // 读寄存器，返回0x10过sub_8122d8c的while
                    if (data == 0)
                    {
                        changeTmp = 0x10;
                        uc.MemWrite(address, Uint2Bytes(changeTmp));
                    }
                    break;
                case SD_CMD_STAT_REG: // 读取SD 命令状态寄存器
                    changeTmp = 1;
                    uc.MemWrite(address, Uint2Bytes(changeTmp));// 写1表示命令回复成功 2超时 4crc校验错误
                    break;
                case SD_DATA_RESP_REG0:
                    // SD 命令响应数据寄存器 r0,r1,r2,r3每个寄存器占用4字节
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD0:// 进入SPI模式
                            //Console.WriteLine($"SD卡 进入SPI模式");
                            break;
                        case SDC_CMD_CMD1:
                            break;
                        case SDC_CMD_CMD2:
                            // 用于请求 SD 卡返回 CID (Card Identification Number)数据(128位响应)
                            // printf("SD卡 获取CID寄存器(%x)\n", SEND_SDDATA_CACHE); 
                            //Console.WriteLine($"SD卡 获取CID寄存器");
                            changeTmp1 = 0xF016C1C4;
                            uc.MemWrite(SD_DATA_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD7:
                            // 用于选择或取消选择一张 SD 卡
                           // Console.WriteLine($"取消或选择SD卡");
                            break;
                        case SDC_CMD_CMD8:
                            //询问SD卡的版本号和电压范围
                            changeTmp1 = 0x1aa;
                            uc.MemWrite(SD_DATA_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD9:
                            // 获取SD卡的CSD寄存器（Card-Specific Data Register）(128位响应)
                            // printf("SD卡 获取CSD寄存器(%x)\n", SEND_SDDATA_CACHE);
                            //Console.WriteLine($"SD卡 获取CSD寄存器");
                            //  changeTmp1 = 0x400E0032;//原始数据
                            changeTmp1 = 0x0000e004;// int*转换到char*
                            uc.MemWrite(SD_DATA_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD55:
                            //用于通知SD卡，下一个命令将是应用命令（ACMD）
                            //Console.WriteLine("SD卡ACMD模式开启");
                            changeTmp1 = 0x20;
                            uc.MemWrite(SD_DATA_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD41_SD:
                            // 初始化SD命令
                            //Console.WriteLine("初始化SD卡"); 
                            //  bit 31 = 1：卡已经准备好，可以进行后续操作。
                            //  bit 30 = 0：该卡为标准容量卡 SDSC，不是 SDHC/SDXC 高容量卡。
                            //  bit 23-15 = 0xFF：卡支持的电压范围是 2.7V到3.6V。
                            changeTmp1 = 0x80FF8000; // 普通容量SD卡
                            uc.MemWrite(SD_DATA_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD3_SD:
                            // SEND_RELATIVE_ADDR (RCA)在 SD 卡的初始化过程中为卡分配一个相对地址
                            // printf("SD卡 分配相对地址(%x)\n", SEND_SDDATA_CACHE); 
                            //Console.WriteLine("SD卡 分配相对地址");
                            changeTmp1 = 0x3001;
                            uc.MemWrite(SD_DATA_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD12:
                            // 结束连续多数据块传输
                            // printf("结束SD卡连续读\n");
                            //Console.WriteLine("结束SD卡连续读");
                            break;
                        case SDC_CMD_CMD13:
                            // 查询 SD 卡的状态，并返回卡的当前状态信息 
                            //Console.WriteLine("SD卡 查询SD卡状态");
                            // printf("SD卡 查询SD卡状态(%x)\n", SEND_SDDATA_CACHE);
                            // 0x100 = R1_READY_FOR_DATA_8
                            changeTmp1 = 0x100;
                            uc.MemWrite(SD_DATA_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD16:
                            // 该命令用于设置数据块的长度
                            //Console.WriteLine("SD卡 设置SD数据块长度");
                            // printf("SD卡 设置SD数据块长度(%x)\n", SEND_SDDATA_CACHE);
                            // DMA_Transfer_Bytes_Count = SEND_SDDATA_CACHE;
                            break;
                        case SDC_CMD_CMD17:// 读取多个数据块
                        case SDC_CMD_CMD18:// 读取单个数据块
                            if (vm_dma_msdc_config.ConfigFinish == 1)
                            {
                                byte[] dataCachePtr = readSDFile(MSDC_DATA_ADDR, vm_dma_msdc_config.TransferCount);
                                if (dataCachePtr != null)
                                {
                                    uc.MemWrite(vm_dma_msdc_config.DataAddr, dataCachePtr);
                                }
                                else
                                {
                                    Console.WriteLine("SD卡 读取数据为null"); 
                                }
                                // msdc dma传输完成
                                    vm_dma_msdc_config.ConfigFinish = 0;
                                changeTmp = 0x8000;
                                uc.MemWrite(SDC_DATSTA_REG, Uint2Bytes(changeTmp));
                                if (vm_dma_msdc_config.TransferEndInterruptEnable == 1)
                                {
                                    vm_dma_msdc_config.TransferEndInterruptEnable = 0;
                                    StartCallback(0x816D9F0 + 1, 0);
                                }
                            }
                            break;
                        case SDC_CMD_CMD24://写多个数据块
                        case SDC_CMD_CMD25://写单个数据块
                            if (vm_dma_msdc_config.ConfigFinish == 1)
                            {
                                vm_dma_msdc_config.ConfigFinish = 0;
                                byte[] buffer = new byte[vm_dma_msdc_config.TransferCount];
                                buffer = uc.MemRead(vm_dma_msdc_config.DataAddr, vm_dma_msdc_config.TransferCount);
                                writeSDFile(buffer, MSDC_DATA_ADDR, vm_dma_msdc_config.TransferCount);
                                changeTmp = 0x8000;
                                uc.MemWrite(SDC_DATSTA_REG, Uint2Bytes(changeTmp));
                                if (vm_dma_msdc_config.TransferEndInterruptEnable == 1)
                                {
                                    vm_dma_msdc_config.TransferEndInterruptEnable = 0;
                                    StartCallback(0x816D9F0 + 1, 0);
                                }
                            }
                            break;
                        case SDC_CMD_ACMD42:
                            // 卡检测信号通常用于检测 SD 卡是否插入或取出
                            // printf("SD卡 检查是否插入或取出(%x)\n", SEND_SDDATA_CACHE);
                            //Console.WriteLine("SD卡 检查是否插入或取出");
                            break;
                        case SDC_CMD_ACMD51:
                            // 请求 SD 卡返回其 SCR (SD Card Configuration Register)寄存器
                            // printf("SD卡 读取SCR寄存器(%x)\n", SEND_SDCMD_CACHE);
                            //Console.WriteLine("SD卡 读取SCR寄存器");
                            break;
                        default:

                            Console.WriteLine($"未处理SD_DATA_RESP_REG_0{MSDC_CMD_CACHE:x}");
                            Console.WriteLine($"lastAddress{lastAddress:x}");

                            // printf("未处理SD_DATA_RESP_REG_0(%x,CMD:%x)", SEND_SDDATA_CACHE, SEND_SDCMD_CACHE);
                            // printf("(%x)\n", lastAddress);
                            break;
                    }
                    break;
                case SD_DATA_RESP_REG1:
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD2:
                            changeTmp1 = 0x77;
                            uc.MemWrite(SD_DATA_RESP_REG1, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD9:
                            changeTmp1 = 0x000ff577;
                            uc.MemWrite(SD_DATA_RESP_REG1, Uint2Bytes(changeTmp1));
                            break;
                        default:
                            // printf("未处理SD_DATA_RESP_REG_1(CMD:%x)", SEND_SDCMD_CACHE);
                            // printf("(%x)\n", lastAddress);
                            break;
                    }
                    break;
                case SD_DATA_RESP_REG2:
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD2:
                            changeTmp1 = 0;
                            uc.MemWrite(SD_DATA_RESP_REG2, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD9:
                            changeTmp1 = 0x00090ff7;
                            uc.MemWrite(SD_DATA_RESP_REG2, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD17:
                            break;  
                        default:
                            // printf("未处理SD_DATA_RESP_REG_2(CMD:%x)", SEND_SDCMD_CACHE);
                            // printf("(%x)\n", lastAddress);
                            break;
                    }
                    break;
                case SD_DATA_RESP_REG3:
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD2:
                            changeTmp1 = 0x3;
                            uc.MemWrite(SD_DATA_RESP_REG3, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD9:
                            changeTmp1 = 0x000004a0;
                            uc.MemWrite(SD_DATA_RESP_REG3, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_ACMD51:
                            changeTmp1 = 0;
                            uc.MemWrite(SD_DATA_RESP_REG3, Uint2Bytes(changeTmp1));
                            break;
                        default:
                            // printf("未处理SD_DATA_RESP_REG_3(CMD:%x)", SEND_SDCMD_CACHE);
                            //  printf("(%x)\n", lastAddress);
                            break;
                    }
                    break;
                case SD_CMD_RESP_REG0:
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD2:
                            changeTmp1 = 0xF016C1C4;
                            uc.MemWrite(SD_CMD_RESP_REG0, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD7:
                            break;
                        case SDC_CMD_CMD13:
                            break;
                        case SDC_CMD_CMD16:
                            break;
                        case SDC_CMD_CMD17:
                            break;
                        case SDC_CMD_CMD18:
                            break;
                        case SDC_CMD_CMD24:
                            break;
                        case SDC_CMD_ACMD42:
                            break;
                        default:
                            // printf("未处理SD_DATA_RESP_REG_0(ACMD:%x)", SEND_SDCMD_CACHE);
                            //  printf("(%x)\n", lastAddress);
                            break;
                    }
                    break;
                case SD_CMD_RESP_REG1:
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD2:
                            changeTmp1 = 0x77;
                            uc.MemWrite(SD_CMD_RESP_REG1, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD13:
                            break;
                        case SDC_CMD_CMD16:
                            break;
                        case SDC_CMD_CMD17:
                            break;
                        case SDC_CMD_CMD18:
                            break;
                        case SDC_CMD_CMD55:
                            break;
                        case SDC_CMD_ACMD51:
                            break;
                        default:
                            changeTmp = 0;
                            uc.MemWrite(SD_CMD_RESP_REG1, Uint2Bytes(changeTmp));
                            break;
                    }
                    break;
                case SD_CMD_RESP_REG2:
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD2:
                            changeTmp1 = 0;
                            uc.MemWrite(SD_CMD_RESP_REG2, Uint2Bytes(changeTmp1));
                            break;
                        case SDC_CMD_CMD3_SD:
                            break;
                        case SDC_CMD_CMD7:
                            break;
                        case SDC_CMD_CMD8:
                            break;
                        case SDC_CMD_CMD9:
                            break;
                        case SDC_CMD_CMD12:
                            break;
                        case SDC_CMD_CMD13:
                            break;
                        case SDC_CMD_CMD17:
                            break;
                        case SDC_CMD_CMD18:
                            break;
                        case SDC_CMD_CMD24:
                            break;
                        case 0x90:
                            break;
                        case SDC_CMD_CMD55:
                            break;
                        case SDC_CMD_ACMD51:
                            break;
                        case 0x40000000:
                            break;
                        default:
                            // printf("未处理SD_DATA_RESP_REG_2(ACMD:%x)", SEND_SDCMD_CACHE);
                            //  printf("(%x)\n", lastAddress);
                            break;
                    }
                    break;
                case SD_CMD_RESP_REG3:
                    switch (MSDC_CMD_CACHE)
                    {
                        case SDC_CMD_CMD2:
                            changeTmp1 = 0x3;
                            uc.MemWrite(SD_CMD_RESP_REG3, Uint2Bytes(changeTmp1));
                            break;
                        case 0x8b3:
                            break;
                        default:
                            // printf("未处理SD_DATA_RESP_REG_3(ACMD:%x)", SEND_SDCMD_CACHE);
                            // printf("(%x)\n", lastAddress);
                            break;
                    }
                    break;
                case SD_ARG_REG:
                    if (data == 1)
                    {
                        MSDC_DATA_ADDR = (uint)value;
                    }
                    break;
                case SD_CMD_REG:
                    if (data == 1)
                    {
                        MSDC_CMD_CACHE = (ushort)(value & 0xffff);
                    }
                    break;
                case 0xF015E327:
                    if (value == 0 && data == 1)
                    {
                        confirm("warning", "sd filesystem mount fail");
                    }
                    break;
                case IRQ_MASK_SET_L:
                    if (data == 1)
                    {
                        IRQ_MASK_SET_L_Data &= ~(uint)value;
                    }
                    break;
                case IRQ_CLR_MASK_L:
                    if (data == 1)
                    {
                        IRQ_MASK_SET_L_Data |= (uint)value;
                    }
                    break;
                case RW_SFI_OUTPUT_LEN_REG:
                    if (data == 1)
                    {
                        SF_C_Frame.sendDataCount =  value;
                    }
                    break;
                case RW_SFI_INPUT_LEN_REG:
                    if (data == 1)
                    {
                        SF_C_Frame.readDataCount =  value;
                    }
                    break;
                case RW_SFI_MAC_CTL:
                    if (data == 1)
                    {
                        changeTmp1 = (uint)value;
                        if ((changeTmp1 & 0xc) == 0xc)
                        {
                            if (SF_C_Frame.cmdRev == 0)
                            {
                                SF_C_Frame.cmdRev = 1;
                            }
                        }
                    }
                    else
                    {
                        if (SF_C_Frame.cmdRev == 1)
                        {
                            changeTmp1 = SF_C_Frame.cacheData[0];
                            SF_C_Frame.cmd = (byte)(changeTmp1 & 0xff);
                            SF_C_Frame.address = (changeTmp1 >> 24) | (((changeTmp1 >> 16) & 0xff) << 8) | (((changeTmp1 >> 8) & 0xff) << 16);
                            switch (SF_C_Frame.cmd)
                            {
                                case 0x2:
                                    // SF_CMD_PAGE_PROG
                                    // 计算页地址
                                    // changeTmp1 = (SF_C_Frame.address / 256) * 256;
                                    // 分别是原前8位，中8位，高8位
                                    // printf("flash addr::%x\n", SF_C_Frame.address);
                                    // 减去1cmd 3addr 就是实际写入长度，所以是 - 4
                                    //  地址4字节对齐
                                    changeTmp = 0x8000000 | SF_C_Frame.address;
                                    

                                    //long [] datas = uints2Longs(SF_C_Frame.cacheData);


                                    //byte[] tmp = longs2Bytes(datas).Skip(8).ToArray();
                                    byte[] tmp = Uints2Bytes(SF_C_Frame.cacheData).Skip(4).ToArray();
                                    //incount++;
                                    //if (incount <= 16)
                                    //{
                                    //    Console.WriteLine($"Enter {tmp[0]:x} SF_C_Frame.sendDataCount={SF_C_Frame.sendDataCount:x}");
                                    //}

                                    SF_C_Frame.sendDataCount -= 4;
                                    uc_mem_write(MTK,changeTmp, tmp, (int)SF_C_Frame.sendDataCount); 
                                    break;
                                case 0x5:
                                    changeTmp = SF_C_Frame.SR_REG[0];
                                    changeTmp |= (uint)(SF_C_Frame.SR_REG[1] << 8);
                                    changeTmp |= (uint)(SF_C_Frame.SR_REG[2] << 16);
                                    uc_mem_write(MTK, RW_SFI_GPRAM_DATA_REG, Uint2Bytes(changeTmp),4); 
                                    break;
                                case 0x1:
                                    changeTmp = SF_C_Frame.cacheData[0];
                                    SF_C_Frame.SR_REG[0] = (byte)(changeTmp & 0xff);
                                    SF_C_Frame.SR_REG[1] = (byte)((changeTmp >> 8) & 0xff);
                                    SF_C_Frame.SR_REG[2] = (byte)((changeTmp >> 16) & 0xff);
                                    break;
                                case 0x6:
                                case 0xb9:
                                case 0xaf:
                                case 0x38:
                                    break;
                                case 0x9f:
                                    changeTmp = 1;
                                    uc.MemWrite(RW_SFI_GPRAM_DATA_REG, Uint2Bytes(changeTmp));
                                    changeTmp = 2;
                                    uc.MemWrite(RW_SFI_GPRAM_DATA_REG + 4, Uint2Bytes(changeTmp));
                                    changeTmp = 3;
                                    uc.MemWrite(RW_SFI_GPRAM_DATA_REG + 8, Uint2Bytes(changeTmp));
                                    break;
                                case 0xc0:
                                    break;
                                default:
                                    // printf("unhandle flash cmd[%x]\n", SF_C_Frame.cmd);
                                    break;
                            }
                            SF_C_Frame.cmdRev = 0;
                            SF_C_Frame.cmd = 0;
                            changeTmp = 2;
                            uc.MemWrite(RW_SFI_MAC_CTL, Uint2Bytes(changeTmp));
                        }
                    }
                    break;
                default:
                    if (address >= RW_SFI_GPRAM_DATA_REG && address <= (RW_SFI_GPRAM_DATA_REG + 256))
                    {
                        if (data == 1)
                        {
                            uint off = address - RW_SFI_GPRAM_DATA_REG;
                            off /= 4;
                            //if (incount <= 16)
                            //{
                            //    Console.WriteLine($" off= {off} value={value:x}");
                            //}
                            SF_C_Frame.cacheData[off] = value;
                            
                        }
                    }
                    /*
                      // 声音相关寄存器
                      if (address >= 0x83000000 && address <= 0x84000000)
                      {
                          if (data == 1)
                          {
                              printf("[Sound]%x", address);
                              printf(" %x\n", value);
                          }
                      }*/
                                    /*
                                    if (data == 2)
                                    {
                                        sprintf(globalSprintfBuff, "address (%x) is unmapping", address);
                                        confirm("memory read error", globalSprintfBuff);
                                    }
                                    else if (data == 3)
                                    {
                                        sprintf(globalSprintfBuff, "address(%x) is unmapping", address);
                                        confirm("memory write error", globalSprintfBuff);
                                    }
                                    else if (data == 4)
                                    {
                                        sprintf(globalSprintfBuff, "address (%x),code is %d", address, data);
                                        confirm("error memory operation", globalSprintfBuff);
                                    }*/
                    break;
            }
            /*
              if (address == 0x4b000 && data == 1)
              {
                  printf("la======%x====", lastAddress);
                  address=0;
              }*/

        }

        private static long[] uints2Longs(uint[] cacheData)
        {
            long[] ret = new long[cacheData.Length];
            for(int i = 0; i < cacheData.Length; i++)
            {
                ret[i] = cacheData[i];
            }
            return ret;
        }

        private static void confirm(string title, string message)
        {
            Console.WriteLine(title + " " + message);
            //MessageBox.Show(message, title);
        }

        public static FileStream SD_File_Handle = null;
        static bool writeSDFile(byte[] Buffer, uint startPos, uint size)
        {
            //Console.WriteLine("writeSDFile");
            byte flag;
            if (SD_File_Handle == null)
            {
                Console.WriteLine("writeSDFile SD_File_Handle = null");
                return false;
            }

            try
            {
                // 移动文件指针
                if (SD_File_Handle.Seek(startPos, SeekOrigin.Begin) < 0)
                {
                    Console.WriteLine("移动文件指针失败");
                    return false;
                }

                // 写入文件
                SD_File_Handle.Write(Buffer, 0, (int)size);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"写入文件失败: {ex.Message}");
                return false;
            }
        }


        /// <summary>
        /// 执行函数回调
        /// </summary>
        /// <param name="callbackFuncAddr">回调函数地址</param>
        /// <param name="r0">R0寄存器参数值</param>
        static void StartCallback(uint callbackFuncAddr, uint r0)
        {
            Console.WriteLine("StartCallback");
            uint backAddr = 0;
            uint lr = CPU_ISR_CB_ADDRESS + 8;

            // 读取当前PC值
            backAddr = uc_reg_read( Arm.UC_ARM_REG_PC);

            // 保存CPU上下文 
            SaveCpuContext(ref stackCallback, backAddr); 
            // 设置寄存器值开始回调
            uc_reg_write(MTK, Arm.UC_ARM_REG_R0, r0);
            uc_reg_write(MTK, Arm.UC_ARM_REG_PC, callbackFuncAddr);
            uc_reg_write(MTK, Arm.UC_ARM_REG_LR, lr);
        }

        static void uc_reg_write(IBackend uc, int reg, uint data)
        { 
            uc.RegWrite(reg, data);
        }

        static void uc_reg_readRef(IBackend uc, int reg,ref uint data)
        {
            //byte[] tmpdata = new byte[4];
            //uc_reg_read(reg, tmpdata);
            //data = Bytes2Uint(tmpdata);

            data = uc_reg_read(reg);

        }
        /// <summary>
        /// 读取SD卡文件内容（安全版本）
        /// </summary>
        private static byte[] readSDFile(uint startPos, uint size)
        {
            //Console.WriteLine("readSDFile");
            if (SD_File_Handle == null)
            {
                Console.WriteLine("SD_File_Handle is null ");
                return null;
            }

            try
            {
                // 移动文件指针
                if (SD_File_Handle.Seek(startPos, SeekOrigin.Begin) < 0)
                {
                    Console.WriteLine("移动文件指针失败");
                    return null;
                }

                // 读取文件内容
                byte[] buffer = new byte[size];
                int bytesRead = SD_File_Handle.Read(buffer, 0, (int)size);

                if (bytesRead != size)
                {
                    Console.WriteLine("读取SD卡文件失败");
                    return null;
                }

                return buffer;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"操作失败: {ex.Message}");
                return null;
            }
        }
        /// <summary>
        /// SIM卡数据处理函数
        /// </summary>
        /// <param name="sim_dev">SIM设备实例</param>
        /// <param name="sim_num">SIM卡编号(0/1)</param>
        /// <param name="isWrite">读写标志(0=读,1=写)</param>
        /// <param name="value">写入的值</param>
        static void SIM_DATA_HANDLE(ref VM_SIM_DEV sim_dev, byte sim_num, byte isWrite, uint value)
        {
            if (isWrite == 0) // 读操作
            {
                // 从接收缓冲区读取数据
                changeTmp1 = sim_dev.RxBuffer[sim_dev.RxBufferIndex++];
                sim_dev.RxCurrentIndex++;
                sim_dev.RxRemainCount--;

                // 更新寄存器状态
                uc_mem_write(MTK, SIM2_COUNT, Uint2Bytes(sim_dev.RxRemainCount), 4);

                // 根据SIM卡编号写入不同寄存器
                if (sim_num == 0)
                    uc_mem_write(MTK, SIM1_DATA, ref changeTmp1, 4);
                else if (sim_num == 1)
                    uc_mem_write(MTK, SIM2_DATA, ref changeTmp1, 4);

                Console.WriteLine($"[sim{sim_num}] read data({changeTmp1:x2})(last:{lastAddress:x})");
            }
            else // 写操作
            {
                // 写入发送缓冲区
                sim_dev.TxBuffer[sim_dev.TxBufferIndex++] = (byte)value;
                Console.WriteLine($"[sim{sim_num}] write data({value:x2})");
            }
        }

        /// <summary>
        /// SIM卡基础控制处理
        /// </summary>
        /// <param name="sim_dev">SIM设备结构体</param>
        /// <param name="sim_num">SIM卡编号(0/1)</param>
        /// <param name="value">控制值</param>
        static void SIM_BASE_HANDLE(ref VM_SIM_DEV sim_dev, byte sim_num, uint value)
        {
            sim_dev.Control = (uint)value;  // 显式转换为uint以匹配原u32类型
            Console.WriteLine($"[sim{sim_num}] control({value:x})");
        }

        /// <summary>
        /// SIM卡中断使能处理
        /// </summary>
        /// <param name="sim_dev">SIM设备结构体</param>
        /// <param name="sim_num">SIM卡编号(0/1)</param>
        /// <param name="value">中断使能值</param>
        static void SIM_IRQ_HANDLE(ref VM_SIM_DEV sim_dev, byte sim_num, uint value)
        {
            sim_dev.IrqEnable = (uint)value;

            var sb = new StringBuilder();
            sb.Append($"[sim{sim_num}] irq enable");
            sb.Append($"({lastAddress:x})");

            // 检查各中断标志位
            if ((value & (int)SIM_IRQ_CHANNEL.SIM_IRQ_TX) != 0)
                sb.Append(" [TX] ");
            if ((value & (int)SIM_IRQ_CHANNEL.SIM_IRQ_RX) != 0)
                sb.Append(" [RX] ");
            if ((value & (int)SIM_IRQ_CHANNEL.SIM_IRQ_TOUT) != 0)
                sb.Append(" [TOUT] ");
            if ((value & (int)SIM_IRQ_CHANNEL.SIM_IRQ_NOATR) != 0)
                sb.Append(" [NOATR] ");
            if ((value & (int)SIM_IRQ_CHANNEL.SIM_IRQ_RXERR) != 0)
                sb.Append(" [RXERR] ");
            if ((value & (int)SIM_IRQ_CHANNEL.SIM_IRQ_T0END) != 0)
                sb.Append(" [T0END] ");
            if ((value & (int)SIM_IRQ_CHANNEL.SIM_IRQ_T1END) != 0)
                sb.Append(" [T1END] ");
            if ((value & 0xFFFFFFFF) == 0)  // 修正原代码中的位运算错误
                sb.Append(" [NONE]");

            sb.Append($"({value:x})");
            Console.WriteLine(sb.ToString());
        }
        static byte[] SIM_ATR_RSP_DATA = { 0x3b, 0x00, 1, 2, 3, 4, 5, 6 };
        /// <summary>
        /// SIM卡TIDE(时间间隔与数据交换)处理
        /// </summary>
        /// <param name="sim_dev">SIM设备结构体</param>
        /// <param name="sim_num">SIM卡编号(0/1)</param>
        /// <param name="value">配置值</param>
        static void SIM_TIDE_HANDLE(ref VM_SIM_DEV sim_dev, byte sim_num, uint value)
        {
            // 设置触发计数
            sim_dev.RxTriggerCount = (uint)(value & 0xF) + 1;
            sim_dev.TxTriggerCount = (uint)((value >> 16) & 0xF) + 1;
            Console.WriteLine($"[sim{sim_num}]TIDE(tx:{sim_dev.TxTriggerCount})(rx:{sim_dev.RxTriggerCount})");

            switch (sim_dev.Event)
            {
                case SIM_DEV_EVENT.SIM_DEV_EVENT_NONE:
                    // ATR初始化处理
                    uint changeTmp2 = (uint)SIM_ATR_RSP_DATA.Length;
                    sim_dev.RxRemainCount = (byte)changeTmp2;
                    MyMemcpy(sim_dev.RxBuffer, SIM_ATR_RSP_DATA, (int)changeTmp2);
                    sim_dev.RxBufferIndex = 0;
                    sim_dev.RxCurrentIndex = 0;
                    sim_dev.IrqChannel = SIM_IRQ_CHANNEL.SIM_IRQ_RX;
                    sim_dev.IrqStart = true;
                    sim_dev.Event = SIM_DEV_EVENT.SIM_DEV_EVENT_ATR_PRE;

                    changeTmp1 = sim_dev.RxRemainCount;
                    uc_mem_write(MTK, sim_num == 0 ? SIM1_COUNT : SIM2_COUNT, ref changeTmp1, 4);
                    Console.WriteLine($"[sim{sim_num}]开始发送TS、T0两个字节");
                    break;

                case SIM_DEV_EVENT.SIM_DEV_EVENT_ATR_PRE:
                    // TS,T0发送完成处理
                    Console.WriteLine($"[sim{sim_num}]检查历史字节");
                    sim_dev.RxCurrentIndex = 0;

                    // 解析T0字节
                    byte t0 = sim_dev.RxBuffer[1];
                    if ((t0 & 0x80) != 0)  // 检查最高位
                    {
                        byte len = (byte)(t0 & 0x0F);
                        changeTmp1 = Math.Min(sim_dev.RxRemainCount, len);
                        uc_mem_write(MTK, SIM1_COUNT, ref changeTmp1, 4);

                        if (sim_dev.RxRemainCount > len)
                        {
                            // 需要多次中断
                            sim_dev.Event = SIM_DEV_EVENT.SIM_DEV_EVENT_ATR_PRE;
                        }
                        else
                        {
                            sim_dev.Event = SIM_DEV_EVENT.SIM_DEV_EVENT_CMD;
                        }

                        sim_dev.IrqChannel = SIM_IRQ_CHANNEL.SIM_IRQ_RX;
                        sim_dev.IrqStart = true;
                    }
                    else
                    {
                        // 无历史字节
                        sim_dev.Event = SIM_DEV_EVENT.SIM_DEV_EVENT_CMD;
                    }
                    break;

                default:
                    break;
            }
        }

        private static byte[] Uints2Bytes(uint[] uintArray)
        {
            byte[] byteArray = new byte[uintArray.Length * sizeof(uint)];
            Buffer.BlockCopy(uintArray, 0, byteArray, 0, byteArray.Length);
            return byteArray;
        }
        private static byte[] Uint2Bytes(uint uintdata,int count=4)
        {
            byte[] data = Uints2Bytes(new uint[] { uintdata });
            return data.Take(count).ToArray();
        }
        private static uint[] Bytes2Uints(byte[] byteArray)
        {
            // 检查字节数组长度是否合法（必须是 4 的倍数，因为 1 uint = 4 bytes）
            if (byteArray.Length % sizeof(uint) != 0)
            {
                throw new ArgumentException("字节数组长度必须是 4 的倍数", nameof(byteArray));
            }

            uint[] uintArray = new uint[byteArray.Length / sizeof(uint)];
            Buffer.BlockCopy(byteArray, 0, uintArray, 0, byteArray.Length);
            return uintArray;
        }

        private static uint Bytes2Uint(byte[] byteArray)
        {
            if (byteArray.Length != 4)
            {
                throw new ArgumentException("字节数组长度必须是 4 ", nameof(byteArray));
            }
            uint[] ret = Bytes2Uints(byteArray);
            return ret[0];
        }

        //private static byte[] Uints2Bytes(uint[] uintArray)
        //{
        //    byte[] byteArray = new byte[uintArray.Length * sizeof(uint)];
        //    Buffer.BlockCopy(uintArray, 0, byteArray, 0, byteArray.Length);
        //    return byteArray;
        //}

        private static byte[] longs2Bytes(long[] uintArray)
        {
            byte[] byteArray = new byte[uintArray.Length * sizeof(long)];
            Buffer.BlockCopy(uintArray, 0, byteArray, 0, byteArray.Length);
            return byteArray;
        }

        //public unsafe static byte[] Uint2Bytes(uint uintdata,int size = 4)
        //{
        //    byte[] byteArray = new byte[size];

        //    // 固定 byte[] 内存，防止 GC 移动
        //    fixed (byte* pBytes = byteArray)
        //    {
        //        // 直接复制 uint 的内存到 byte[]
        //        *(uint*)pBytes = uintdata;
        //    }

        //    return byteArray;
        //}


        //public unsafe static byte[] Uint2Bytes(long uintdata)
        //{
        //    byte[] byteArray = new byte[sizeof(uint)];

        //    // 固定 byte[] 内存，防止 GC 移动
        //    fixed (byte* pBytes = byteArray)
        //    {
        //        // 直接复制 uint 的内存到 byte[]
        //        *(long*)pBytes = uintdata;
        //    }

        //    return byteArray;
        //}


        //public unsafe static byte[] Uint2BytesRef(ref uint uintdata)
        //{
        //    byte[] byteArray = new byte[sizeof(uint)];

        //    // 固定 byte[] 内存，防止 GC 移动
        //    fixed (byte* pBytes = byteArray)
        //    {
        //        // 直接复制 uint 的内存到 byte[]
        //        *(uint*)pBytes = uintdata;
        //    }

        //    return byteArray;
        //}

        //public unsafe static byte[] int2BytesRef(ref int uintdata)
        //{
        //    byte[] byteArray = new byte[sizeof(uint)];

        //    // 固定 byte[] 内存，防止 GC 移动
        //    fixed (byte* pBytes = byteArray)
        //    {
        //        // 直接复制 uint 的内存到 byte[]
        //        *(int*)pBytes = uintdata;
        //    }

        //    return byteArray;
        //}
        //public unsafe static byte[] int2BytesRef(ref uint uintdata)
        //{
        //    byte[] byteArray = new byte[sizeof(long)];

        //    // 固定 byte[] 内存，防止 GC 移动
        //    fixed (byte* pBytes = byteArray)
        //    {
        //        // 直接复制 uint 的内存到 byte[]
        //        *(long*)pBytes = uintdata;
        //    }

        //    return byteArray;
        //}


        ///// <summary>
        ///// 直接共享内存
        ///// </summary>
        ///// <param name="byteArray"></param>
        ///// <returns></returns>
        ///// <exception cref="ArgumentException"></exception>
        //public unsafe static uint[] Bytes2Uints(byte[] byteArray)
        //{
        //    if (byteArray.Length % sizeof(uint) != 0)
        //    {
        //        throw new ArgumentException("字节数组长度必须是 4 的倍数", nameof(byteArray));
        //    }

        //    fixed (byte* pBytes = byteArray)
        //    {
        //        uint* pUints = (uint*)pBytes;
        //        // 创建一个新的 uint[]，但直接指向 byte[] 的内存（危险！）
        //        uint[] uintArray = new uint[byteArray.Length / sizeof(uint)];
        //        for (int i = 0; i < uintArray.Length; i++)
        //        {
        //            uintArray[i] = pUints[i];
        //        }
        //        return uintArray;
        //    }
        //}


        //public unsafe static uint Bytes2Uint(byte[] byteArray)
        //{
        //    if (byteArray.Length != sizeof(uint))
        //    {
        //        throw new ArgumentException("字节数组长度必须是 4", nameof(byteArray));
        //    }
        //    fixed (byte* pBytes = byteArray)
        //    {
        //        // 直接读取 byte[] 的内存作为 uint
        //        return *(uint*)pBytes;
        //    }
        //}


        public class hookCodeCallBackClass : ICodeHook
        {
            public void hook(IBackend uc, long addresslong, int size, object user_data)
            {
                uint address = (uint)addresslong;
                byte[] globalSprintfBuff = new byte[128];

                uint lastSIM_DMA_ADDR = 0;

                //Console.WriteLine($"address = ({address:X})");
                bool isdef = false;
                switch (address)
                {
                    case 0x8370220: // 直接返回开机流程任务全部完成
                        changeTmp1 = 1;
                        uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp1);
                        break;

                    case 0x81b38d0:
                        changeTmp1 = uc_reg_read(Arm.UC_ARM_REG_R1);
                        Console.WriteLine($"l1audio_sethandler({changeTmp1:x})");
                        break;

                    case 0x8087256:
                        changeTmp1 = uc_reg_read(Arm.UC_ARM_REG_R0);
                        Console.WriteLine($"sim_check_status v26({changeTmp1:x})");
                        break;

                    case 0x80D2EE0:
                        changeTmp1 = uc_reg_read(Arm.UC_ARM_REG_R2);
                        lastSIM_DMA_ADDR = changeTmp1;
                        Console.WriteLine($"SIM_CMD(r0,r1,rx_result:{changeTmp1:x})");
                        break;

                    case 0x819f5b4:
                        changeTmp1 = uc_reg_read(Arm.UC_ARM_REG_R0);
                        globalSprintfBuff = uc.MemRead(changeTmp1, globalSprintfBuff.Length);
                        byte[] buftemp = globalSprintfBuff.TakeWhile(b => b != 0).ToArray();
                        Console.WriteLine($"kal_debug_print({System.Text.Encoding.UTF8.GetString(buftemp)})({lastAddress:x})");
                        break;

                    case 0x82D2A22: // mr_sprintf
                        globalSprintfBuff = uc.MemRead(0xF028EDC4, globalSprintfBuff.Length);
                        byte[] buftemp2 = globalSprintfBuff.TakeWhile(b => b != 0).ToArray();
                        Console.WriteLine($"mr_sprintf({System.Text.Encoding.UTF8.GetString(buftemp2)})");
                        break;

                    case 0x81a4d54:
                        changeTmp1 = uc_reg_read(Arm.UC_ARM_REG_R0);
                        globalSprintfBuff = uc.MemRead(changeTmp1, globalSprintfBuff.Length);
                        byte[] buftemp3 = globalSprintfBuff.TakeWhile(b => b != 0).ToArray();
                        Console.WriteLine($"dbg_print({System.Text.Encoding.UTF8.GetString(buftemp3)})[{lastAddress:X}]");
                        break;

                    case 0x83D1C28: // mr_mem_get()
                        changeTmp1 = 0;
                        uc.MemWrite(0xF0166068, Uint2Bytes((uint)changeTmp1));
                        break;

                    case 0x83890C8:
                        // srv_charbat_get_charger_status默认返回1，是充电状态
                        changeTmp1 = 1;
                        uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp1);
                        break;

                    case 0x80E7482:
                        // 强制过 nvram_util_caculate_checksum检测
                        changeTmp = uc_reg_read(Arm.UC_ARM_REG_R0);
                        changeTmp1 = uc_reg_read(Arm.UC_ARM_REG_R2);
                        uc.RegWrite(Arm.UC_ARM_REG_R2, changeTmp);
                        break;

                    case 0x8093FB2: // 强制过8093ffa方法
                        changeTmp = 1;
                        uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp);
                        break;

                    case 0x80D2CA4:
                        // 过sub_80D2CA4
                        changeTmp = uc_reg_read(Arm.UC_ARM_REG_R5);
                        changeTmp2 = 0xff;
                        //Console.WriteLine($"过sub_80D2CA4 {changeTmp:x}");
                        uc.MemWrite(changeTmp + 3, Uint2Bytes(changeTmp2, 1));
                        break;

                    case 0x80601ec:
                    case 0x80601ac: // 过sub_8060194的while(L1D_WIN_Init_SetCommonEvent)
                        changeTmp = uc_reg_read(Arm.UC_ARM_REG_R0);
                        //Console.WriteLine($"0x80601ac = ({changeTmp:x})");
                        byte[] tmp = Uint2Bytes(changeTmp, 4);
                        //Console.WriteLine($"0x80601ac = ({tmp[0]:x})");
                        uc.MemWrite(TMDA_BASE, Uint2Bytes(changeTmp, 4));
                        break;

                    case 0x8223F66: //过sub_8223f5c(L1层的) 暂时去不掉
                        changeTmp = 0;
                        uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp);
                        break;

                    case 0x800DA28: // 暂时去不掉
                        changeTmp = 0;
                        uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp);
                        //Console.WriteLine($"0x800DA28({changeTmp:x})"); 
                        break;

                    default:
                        isdef = true;
                        break;
                }
                //if (isdef == false)
                //{
                //    Console.WriteLine($"address({address:x})");
                //}
                //else
                //{ 
                //    Console.WriteLine($"address({address:x})");
                //}

                //if(address== 0x8002e38)
                //{
                //    Console.WriteLine($"address({address:x})");
                //}
                //if (address == 0x81b466c)
                //{
                //    Console.WriteLine($"address({address:x})");
                //}

                lastAddress = address;
            }
        }

        private static uint uc_reg_read(int reg)
        {
            return (uint)MTK.RegRead(reg);
        }
        private static void uc_reg_read(int reg,ref uint value)
        {
            value = (uint)MTK.RegRead(reg);
        }

        public class BlockCallBackClass:IBlockHook
        { 
            public void hook(IBackend uc, long addresslong, int size, object user_data)
            {
                uint address = (uint)addresslong;
                VmEvent vmEvent;
                uint tmp2 = 0;
                if (user_data.GetType() == typeof(UInt32))
                {
                    tmp2 = (uint)(user_data);
                }
                else if (user_data.GetType() == typeof(Int32))
                {
                    int tmp = (int)user_data;
                    tmp2 = (uint)(tmp);
                }
                else
                {
                    Console.WriteLine($"not support: {user_data}");
                }
                // Console.WriteLine("user_data " + user_data);
                switch (tmp2)
                {
                    case 4: // 中断恢复 
                        if (irq_nested_count > 0)
                        {
                            RestoreCpuContext(ref isrStackList[--irq_nested_count]);
                        }
                        break;
                    case 5: // 回调恢复 
                        RestoreCpuContext(ref stackCallback);
                        break;
                    case 7:
                        // 过方法sub_87035D4 (0x4000801E)
                        changeTmp = 1;
                        uc.RegWrite(Arm.UC_ARM_REG_R0, changeTmp);

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
                                            SimulatePressKey((byte)vmEvent.R0, (byte)vmEvent.R1);
                                        else // 如果处理失败，重新入队
                                            EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                        break;
                                    case VM_EVENT.VM_EVENT_SIM_IRQ:
                                        // 进入usim中断
                                        changeTmp1 = vmEvent.R0;
                                        if (vmEvent.R1 == 0)
                                        {
                                            uc.MemWrite(SIM1_IRQ_STATUS, Uint2Bytes(changeTmp1)); // 卡一
                                            if (!StartInterrupt(5, address))
                                            {
                                                EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                            }
                                        }
                                        if (vmEvent.R1 == 1)
                                        {
                                            uc.MemWrite(SIM2_IRQ_STATUS, Uint2Bytes(changeTmp1)); // 卡二 
                                            if (!StartInterrupt(28, address))
                                            {
                                                EnqueueVMEvent(vmEvent.Event, vmEvent.R0, vmEvent.R1);
                                            }
                                        }
                                        break;
                                    case VM_EVENT.VM_EVENT_SIM_T0_TX_END:
                                        if (vmEvent.R0 == 0)
                                        {
                                            HandleSimTxCmd(ref vm_sim1_dev, (byte)vmEvent.R0, vm_dma_sim1_config.TransferCount, vm_dma_sim1_config.DataAddr);
                                        }
                                        else if (vmEvent.R0 == 1)
                                        {
                                            HandleSimTxCmd(ref vm_sim2_dev, (byte)vmEvent.R0, vm_dma_sim2_config.TransferCount, vm_dma_sim2_config.DataAddr);
                                        }
                                        break;
                                    case VM_EVENT.VM_EVENT_SIM_T0_RX_END:
                                        if (vmEvent.R0 == 0)
                                        {
                                            HandleSimRxCmd(ref vm_sim1_dev, (byte)vmEvent.R0, vm_dma_sim1_config.TransferCount, vm_dma_sim1_config.DataAddr);
                                        }
                                        else if (vmEvent.R0 == 1)
                                        {
                                            HandleSimRxCmd(ref vm_sim2_dev, (byte)vmEvent.R0, vm_dma_sim2_config.TransferCount, vm_dma_sim2_config.DataAddr);
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
                                        Update_RTC_Time();
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
        }
        

        static  void SaveCpuContext(ref uint[] stackCallbackPtr, uint backAddr)
        {
            //Console.WriteLine("SaveCpuContext");
            //byte[] stackCallbackPtrTmp = new byte[stackCallbackPtr.Length * 4];  
            stackCallbackPtr[0] = uc_reg_read(Arm.UC_ARM_REG_CPSR); 

            //stackCallbackPtr = Bytes2Uints(stackCallbackPtrTmp); 
            if ((stackCallbackPtr[0] & 0x20) !=0)
            { 
                backAddr += 1;
            }
            int[] regs = new int[] { Arm.UC_ARM_REG_R0, Arm.UC_ARM_REG_R1, Arm.UC_ARM_REG_R2, Arm.UC_ARM_REG_R3, Arm.UC_ARM_REG_R4, Arm.UC_ARM_REG_R5, Arm.UC_ARM_REG_R6, Arm.UC_ARM_REG_R7, Arm.UC_ARM_REG_R8, Arm.UC_ARM_REG_R9, Arm.UC_ARM_REG_R10, Arm.UC_ARM_REG_R11, Arm.UC_ARM_REG_R12, Arm.UC_ARM_REG_R13, Arm.UC_ARM_REG_LR };
            //uint*[] addr = new uint*[15];
            //for (int i = 0; i < 15; i++)
            //{
            //    addr[i] = stackCallbackPtr++;
            //} 
            // 保存状态 
            uc_reg_read_batch(MTK,regs, ref stackCallbackPtr, 1,15);
            stackCallbackPtr[16] = backAddr;
        }

        private  static void uc_reg_read_batch(IBackend uc, int[] regs, ref uint[] stackCallbackPtr,int start,int count)
        {
            for (int i = 0; i < count; i++)
            {
                //byte[] tmpbytes = new byte[4];
                //uc_reg_read(regs[i], tmpbytes);
                //uint data = Bytes2Uint(tmpbytes);
                //stackCallbackPtr[i + start] = data;
                uint nowdata = uc_reg_read(regs[i]);
                //Console.WriteLine($"uc_reg_read_batch {i+ start} = {nowdata:x}");
                stackCallbackPtr[i + start] = nowdata;
            } 
        }

        private static void RestoreCpuContext(ref uint[] stackCallback)
        {
            //Console.WriteLine("恢复CPU上下文");
            // 恢复CPU上下文
            // 还原状态
            int[] regs =  { Arm.UC_ARM_REG_CPSR, Arm.UC_ARM_REG_R0, Arm.UC_ARM_REG_R1, Arm.UC_ARM_REG_R2, Arm.UC_ARM_REG_R3, Arm.UC_ARM_REG_R4, Arm.UC_ARM_REG_R5, Arm.UC_ARM_REG_R6, Arm.UC_ARM_REG_R7, Arm.UC_ARM_REG_R8, Arm.UC_ARM_REG_R9, Arm.UC_ARM_REG_R10, Arm.UC_ARM_REG_R11, Arm.UC_ARM_REG_R12, Arm.UC_ARM_REG_R13, Arm.UC_ARM_REG_LR, Arm.UC_ARM_REG_PC };
            uc_reg_write_batch(MTK, regs,ref stackCallback, 17); 

        }

        private static void uc_reg_write_batch(IBackend uc, int[] regs, ref uint[] v2stackCallback , int count)
        { 
            for(int i = 0; i < count; i++)
            {
                uint nowdata = v2stackCallback[i]; 
                //Console.WriteLine($"uc_reg_read_batch {i} = {nowdata:x}");
                uc.RegWrite(regs[i], nowdata);
            } 
        }
        // 是否禁用IRQ中断
        static bool isIRQ_Disable(uint cpsr)
        {
            return (cpsr & (1 << 7)) !=0 ;
        }

        // 通过中断进行回调
        private static bool StartInterrupt(int irq_line, uint lastAddr)
        {
             
            // 检查 IRQ 是否被屏蔽
            if ((IRQ_MASK_SET_L_Data & (1 << irq_line) )!=0 )
            {
                //byte[] tmpdata = new byte[4];

                //MTK.RegRead( Arm.UC_ARM_REG_CPSR, tmpdata );
                //changeTmp = Bytes2Uint(tmpdata); 
                uc_reg_read(Arm.UC_ARM_REG_CPSR, ref changeTmp); 

                if (!isIRQ_Disable(changeTmp))
                {
                    changeTmp1 = (uint)(CPU_ISR_CB_ADDRESS + 4); 
                    SaveCpuContext(ref isrStackList[irq_nested_count++],lastAddr); 
                    MTK.RegWrite(Arm.UC_ARM_REG_LR, changeTmp1);// LR更新为特殊寄存器 
                    changeTmp1 = (uint)irq_line;

                    MTK.MemWrite(IRQ_Status, Uint2Bytes(changeTmp1));
                    changeTmp1 = IRQ_HANDLER;
                    // 跳转到中断入口
                    MTK.RegWrite(Arm.UC_ARM_REG_PC, changeTmp1);
                    //Console.WriteLine("true");
                    return true;
                }
            }
            //Console.WriteLine("false");
            return false;
        }

        /**
        key_pad_comm_def->keypad[72]解释index=17表示开机按钮
        假如key_pad[2] = 0x3d；kbd_map_temp_reg=0x3d，值匹配，就是按下按键2
        另外keypad中0-16对应kbd_map_temp_reg中低16位
        另外keypad中17-32对应kbd_map_temp_reg中高16位
        另外keypad中33-48对应kbd_map_temp_reg1中低16位
        另外keypad中49-72对应kbd_map_temp_reg1中高16位
        */
               static byte[] keypaddef =new byte[77] {
            /*keypad*/
            0x12, 0x49, 0x0F, 0x1A,
            0x15, 0xFE, 0xFE, 0xFE,
            0x17, 0x10, 0x03, 0x02,
            0x01, 0x11, 0xFE, 0xFE,
            0xFE, 0x17, 0x1B, 0x06,
            0x05, 0x04, 0x0E, 0xFE,
            0xFE, 0xFE, 0x17, 0x7B,
            0x09, 0x08, 0x07, 0x14,
            0xFE, 0xFE, 0xFE, 0x17,
            0x7C, 0x0B, 0x00, 0x0A,
            0x16, 0xFE, 0xFE, 0xFE,
            0x17, 0xFE, 0xFE, 0xFE,
            0xFE, 0xFE, 0xFE, 0xFE,
            0xFE, 0x17, 0xFE, 0xFE,
            0xFE, 0xFE, 0xFE, 0xFE,
            0xFE, 0xFE, 0x17, 0xFE,
            0xFE, 0xFE, 0xFE, 0xFE,
            0xFE, 0xFE, 0xFE, 0x17,
            /* period */
            0xC4, 0x09, 0x00, 0x00,
            /* power_key_index */
            0x17};


        public static void SimulatePressKey(byte key, byte is_press)
        {
            // 模拟按键
            Console.WriteLine($"模拟按键 {key:x} {is_press}");
            byte kv = 0;
            bool found = false;
            for (byte i = 0; i < 72; i++)
            {
                if (keypaddef[i] == key)
                {
                    found = true;
                    kv = i;
                    break;
                }
            }
            if (found)
            {
                // kv是对应的寄存器第几位
                changeTmp = 1;                                // 状态改变
                MTK.MemWrite( 0x81070000, Uint2Bytes(changeTmp)); // 有按键按下

                changeTmp = (uint)((kv >= 0 && kv < 16) ? (is_press << kv) : 0);
                changeTmp = 0xffff & (~changeTmp);
                MTK.MemWrite(0x81070004, Uint2Bytes(changeTmp,2));
                changeTmp = (uint)((kv >= 16 && kv < 32) ? (is_press << (kv - 16)) : 0);
                changeTmp = 0xffff & (~changeTmp);

                MTK.MemWrite(0x81070008, Uint2Bytes(changeTmp, 2)); 
                changeTmp = (uint)((kv >= 32 && kv < 48) ? (is_press << (kv - 32)) : 0);
                changeTmp = 0xffff & (~changeTmp);

                MTK.MemWrite(0x8107000C, Uint2Bytes(changeTmp, 2)); 
                changeTmp = (uint)((kv >= 48 && kv < 64) ? (is_press << (kv - 48)) : 0);
                changeTmp = 0xffff & (~changeTmp);

                MTK.MemWrite(0x81070010, Uint2Bytes(changeTmp, 2)); 
                // 连续按下间隔 t = v / 32ms
                changeTmp = 32; 
                MTK.MemWrite(0x81070018, Uint2Bytes(changeTmp, 2)); 
            }  
        }

        public static VmEvent[] VmEventHandleList = Enumerable.Range(0, 256) .Select(_ => new VmEvent()) .ToArray();
        public static VmEvent firstEvent = new VmEvent();
        /// <summary>
        /// 锁，线程锁
        /// </summary>
        static object vm_event_queue_mutex = new object();

        private static VmEvent DequeueVMEvent()
        {
            VmEvent evt = new VmEvent();
            // todo 此处没等待锁，所以要做失败判断
            lock (vm_event_queue_mutex)
            {
                if (VmEventPtr > 0)
                {
                    evt = firstEvent;
                    --VmEventPtr;
                    for (uint i = 0; i < VmEventPtr; i++)
                    {
                        VmEventHandleList[i] = VmEventHandleList[i + 1];
                    }
                }
                return evt; 
            }  
        }
        static byte is_uc_exited = 0;
        public static void EnqueueVMEvent(VM_EVENT eventType, uint r0, uint r1)
        {

            if (is_uc_exited == 1)
                return;

            lock (vm_event_queue_mutex)
            {
                if (VmEventPtr < 256)
                {
                    VmEvent evt = VmEventHandleList[VmEventPtr++];
                    evt.Event = eventType;
                    evt.R0 = r0;
                    evt.R1 = r1;
                }
            }
        }

        static byte[] SIM_CMD_SELECT = { 0xa0, 0xa4, 0x00, 0x00, 0x02 };
        static  byte[] SIM_CMD_GET_RESPONSE = { 0xa0, 0xc0, 0x0, 0x0, 0x16 };

        // 接收设备向SIM发送的命令
        static void HandleSimTxCmd(ref VM_SIM_DEV simDev, byte simNum, uint dataCount, uint dmaDataAddr)
        {
            // 从内存读取SIM卡命令数据
            uc_mem_read(MTK, dmaDataAddr, ref simDev.T0RxData, dataCount);

            Console.WriteLine($"[sim{simNum}]开始解析SIM卡命令(字节数：{dataCount})");

            // 打印发送缓冲区内容
            for (int i = 0; i < simDev.TxBufferIndex; i++)
            {
                Console.Write($"{simDev.TxBuffer[i]:X2} ");
            }
            Console.WriteLine();

            // 检查是否是有效的SIM卡命令
            bool isSelectCmd = simDev.TxBufferIndex == 5 &&
                              MyMemCompare(simDev.TxBuffer, SIM_CMD_SELECT, simDev.TxBufferIndex);
            bool isGetResponseCmd = simDev.TxBufferIndex == 5 &&
                                  MyMemCompare(simDev.TxBuffer, SIM_CMD_GET_RESPONSE, simDev.TxBufferIndex);

            uint changeTmp1 = 0;
            uint changeTmp2 = 0;

            if (isSelectCmd || isGetResponseCmd)
            {
                simDev.RxBufferIndex = 0;
                simDev.RxCurrentIndex = 0;

                if (simDev.TxBuffer[0] == 0xA0) // SIM卡的命令响应
                {
                    if (simDev.TxBuffer[1] == 0xA4) // SELECT FILE命令
                    {
                        Console.Write($"[sim{simNum}]SIM卡命令[select file] ");
                        for (int i = 0; i < dataCount; i++)
                        {
                            Console.Write($"{simDev.T0RxData[i]:X2} ");
                        }
                        Console.WriteLine();

                        simDev.T0TxCount = dataCount;
                        simDev.IrqChannel = SIM_IRQ_CHANNEL.SIM_IRQ_T0END; // 进入中断使接收命令完成
                        simDev.IrqStart = true;
                        changeTmp1 = 0x9F;
                        changeTmp2 = (uint)SIM_RSP_SF_7F20.Length; // 使用数组Length属性
                    }
                    else if (simDev.TxBuffer[1] == 0xC0) // GET RESPONSE命令
                    {
                        changeTmp1 = 0x90;
                        changeTmp2 = 0x00;
                    }

                    // 写入寄存器
                    if (changeTmp1 > 0)
                    {
                        var regAddr1 = simNum == 0 ? SIM1_SW1_REG : SIM2_SW1_REG;
                        var regAddr2 = simNum == 0 ? SIM1_SW2_REG : SIM2_SW2_REG;

                        uc_mem_write(MTK, regAddr1, ref changeTmp1, 4);
                        uc_mem_write(MTK, regAddr2, ref changeTmp2, 4);
                    }
                }
            }

            // 命令处理完成重置索引
            simDev.TxBufferIndex = 0;
        }

        static  byte[] SIM_CMD_SELECT_DF_GSM = new byte[] { 0x7f, 0x20 };

        static byte[] SIM_RSP_SF_7F20 = new byte[] { 0xA0, 0xC0, 0x32, 0x32, 0x0F, 0x32, 0x32, 0x32, 0x08, 0x2F, 0x05, 0x04, 0x34, 0x01, 0xFF, 0x55, 0x01, 0x02, 0x32, 0x32, 0x90, 0x32 };

        // 处理SIM卡向设备发送的数据
        static void HandleSimRxCmd(ref VM_SIM_DEV sim_dev, byte sim_num, uint data_count, uint dma_data_addr)
        {
            Console.WriteLine($"[sim{sim_num}]开始响应SIM命令");

            uint changeTmp1 = 0;
            uint changeTmp2 = 0;

            if (sim_dev.T0TxCount > 0)
            {
                sim_dev.RxBufferIndex = 0;
                sim_dev.RxCurrentIndex = 0;

                if (sim_dev.T0TxCount == 2 && MyMemCompare(sim_dev.T0RxData, SIM_CMD_SELECT_DF_GSM, (int)sim_dev.T0TxCount))
                {
                    Console.WriteLine($"[sim_cmd]select df.gsm({data_count:x})({dma_data_addr:x})");

                    // 复制响应数据
                    uc_mem_write(MTK, dma_data_addr, SIM_RSP_SF_7F20, (int)data_count);
                    sim_dev.IrqChannel = SIM_IRQ_CHANNEL.SIM_IRQ_T0END;
                    sim_dev.IrqStart = true;
                    changeTmp1 = 0x90; // 有数据响应
                    changeTmp2 = 0;
                }
                else
                {
                    Console.WriteLine("未响应的SIM卡命令");
                }

                MyMemset(sim_dev.T0RxData, 0, (int)sim_dev.T0TxCount);
            }

            if (changeTmp1 > 0)
            {
                if (sim_num == 0)
                {
                    uc_mem_write(MTK, SIM1_SW1_REG, ref changeTmp1, 4);
                    uc_mem_write(MTK, SIM1_SW2_REG, ref changeTmp2, 4);
                }
                if (sim_num == 1)
                {
                    uc_mem_write(MTK, SIM2_SW1_REG, ref changeTmp1, 4);
                    uc_mem_write(MTK, SIM2_SW2_REG, ref changeTmp2, 4);
                }
            }
        }

        public static void uc_mem_write(IBackend uc,uint rTC_IRQ_STATUS,byte[]  data, int count)
        {
            byte[] bytes = data.Take(count).ToArray();
            //Console.WriteLine($"uc_mem_write {rTC_IRQ_STATUS:x}");
            uc.MemWrite(rTC_IRQ_STATUS, bytes);
        } 

        /// <summary>
        /// 内存拷贝
        /// </summary>
        /// <param name="dest">目标数组</param>
        /// <param name="src">源数组</param>
        /// <param name="len">拷贝长度</param>
        public static void MyMemcpy(byte[] dest, byte[] src, int len)
        {
            if (dest == null || src == null || len < 0 ||
                len > dest.Length || len > src.Length)
            {
                throw new ArgumentException("Invalid arguments for memory copy");
            }

            Buffer.BlockCopy(src, 0, dest, 0, len);
        }

        /// <summary>
        /// 内存设置
        /// </summary>
        /// <param name="dest">目标数组</param>
        /// <param name="value">填充值</param>
        /// <param name="len">填充长度</param>
        public static void MyMemset(byte[] dest, byte value, int len)
        {
            if (dest == null || len < 0 || len > dest.Length)
            {
                throw new ArgumentException("Invalid arguments for memory set");
            }

            for (int i = 0; i < len; i++)
            {
                dest[i] = value;
            }
        }

        /// <summary>
        /// 内存比较
        /// </summary>
        /// <param name="src">源数组</param>
        /// <param name="dest">目标数组</param>
        /// <param name="len">比较长度</param>
        /// <returns>true表示相等，false表示不相等</returns>
        public static bool MyMemCompare(byte[] src, byte[] dest, int len)
        {
            if (src == null || dest == null || len < 0 ||
                len > src.Length || len > dest.Length)
            {
                throw new ArgumentException("Invalid arguments for memory compare");
            }

            for (int i = 0; i < len; i++)
            {
                if (src[i] != dest[i])
                {
                    return false;
                }
            }
            return true;
        }


        // 更新RTC时钟寄存器
        static void Update_RTC_Time()
        {
            // 获取当前时间
            DateTime now = DateTime.Now;

            // 读取内存值 
            uc_mem_read(MTK, 0x810b0000, ref changeTmp1, 4);

            if (changeTmp1 != 2)
            {
                changeTmp1 = 2; // 2表示计数器中断 1表示闹钟中断
                uc_mem_write(MTK, RTC_IRQ_STATUS, ref changeTmp1, 4);
                changeTmp1 = 0; // 只有秒=0时才会触发更新
            }
            else
            {
                changeTmp1 = (uint)now.Second; // 只有秒=0时才会触发更新
            }

            // 写入时间值到寄存器
            uc_mem_write(MTK, 0x810b0014, ref changeTmp1, 4); // 秒

            changeTmp1 = (uint)now.Minute;
            uc_mem_write(MTK, 0x810b0018, ref changeTmp1, 4); // 分

            changeTmp1 = (uint)now.Hour;
            uc_mem_write(MTK, 0x810B001C, ref changeTmp1, 4); // 时

            changeTmp1 = (uint)now.Day;
            uc_mem_write(MTK, 0x810b0020, ref changeTmp1, 4); // 日

            changeTmp1 = (uint)now.DayOfWeek;
            uc_mem_write(MTK, 0x810b0024, ref changeTmp1, 4); // 星期

            changeTmp1 = (uint)(now.Month - 1); // C#中Month是1-12，tm_mon是0-11
            uc_mem_write(MTK, 0x810b0028, ref changeTmp1, 4); // 月

            changeTmp1 = (uint)(now.Year - 2000); // 手机系统时间是从2000年开始，时间修正
            uc_mem_write(MTK, 0x810b002c, ref changeTmp1, 4); // 年
        }

        private static void uc_mem_write(IBackend uc, uint rTC_IRQ_STATUS, ref uint changeTmp1, int count)
        {
            uc.MemWrite(rTC_IRQ_STATUS, Uint2Bytes(changeTmp1,count));
        }
        //private static void uc_mem_write(Unicorn uc, uint rTC_IRQ_STATUS, ref uint changeTmp1, int count)
        //{
        //    byte[] bytes = Uint2Bytes(changeTmp1).Take(count).ToArray();
        //    uc.MemWrite(rTC_IRQ_STATUS, bytes);
        //}

        //private static void uc_mem_read(Unicorn uc, uint address, ref uint changeTmp1, int v2)
        //{
        //    //byte[] tmpbytes = new byte[v2];
        //    //uc.MemRead(address, tmpbytes);
        //    //changeTmp1 = Bytes2Uint(tmpbytes); 
        //    uc.MemRead(address, Uint2Bytes(changeTmp1)); 
        //}
        private static void uc_mem_read(IBackend uc, uint address, ref uint changeTmp1, int count)
        {
            //Console.WriteLine($"uc_mem_read {address:x}"); 
            byte[] tmpbytes = uc.MemRead(address, count);
            changeTmp1 = Bytes2Uint(tmpbytes);

            //uc.MemRead(address, Uint2Bytes(changeTmp1,count));
        }

        private static void uc_mem_read(IBackend uc, uint address, ref byte[] changeTmp1, uint count)
        { 
            byte[] tmpbytes = uc.MemRead(address, count);
            for (int i = 0; i < count; i++)
            {
                changeTmp1[i] = tmpbytes[i];
            }
        }

        private static uint irq_nested_count = 0;

        private static uint changeTmp = 0;
        private static uint changeTmp1 = 0;
        private static uint changeTmp2 = 0; 
        private static uint changeTmp3 = 0;  

        private static uint VmEventPtr = 0; 

        /// <summary>
        /// 读取文件内容到字节数组
        /// </summary>
        /// <param name="filename">文件名</param>
        /// <param name="size">输出文件大小</param>
        /// <returns>文件内容字节数组，失败返回null</returns>
        public static byte[] ReadFile(string filename, out int size)
        {
            size = 0;

            try
            {
                // 读取文件内容
                byte[] fileData = File.ReadAllBytes(filename);
                size = fileData.Length;
                return fileData;
            }
            catch (Exception ex) when (
                ex is FileNotFoundException ||
                ex is DirectoryNotFoundException)
            {
                Console.WriteLine($"Failed to open file: {filename}");
                return null;
            }
            catch (Exception ex) when (
                ex is IOException ||
                ex is UnauthorizedAccessException)
            {
                Console.WriteLine($"Failed to read file: {filename}");
                return null;
            }
        }

        /// <summary>
        /// 写入数据到文件
        /// </summary>
        /// <param name="filename">文件名</param>
        /// <param name="buffer">要写入的数据</param>
        /// <param name="size">数据大小</param>
        /// <returns>实际写入的字节数，失败返回0</returns>
        public static int WriteFile(string filename, byte[] buffer, uint size)
        {
            try
            {
                File.WriteAllBytes(filename, buffer);
                return (int)size;
            }
            catch (Exception ex) when (
                ex is IOException ||
                ex is UnauthorizedAccessException ||
                ex is DirectoryNotFoundException)
            {
                Console.WriteLine($"Failed to write file: {filename}");
                return 0;
            }
        }

        /// <summary>
        /// 运行ARM程序模拟
        /// </summary>
        /// <param name="startAddrObj">起始地址对象</param>
        public static void RunArmProgram(uint startAddress)
        {
            // 初始化SIM卡ATR响应数据
            vm_sim1_dev.Event = (SIM_DEV_EVENT)VM_EVENT.VM_EVENT_NONE;
            vm_sim1_dev.IsRst = 0;
            vm_sim1_dev.TxBufferIndex = 0;
            vm_sim1_dev.RxBufferIndex = 0; 

            // 启动前工作
            // changeTmp = 1;
            // uc_mem_write(MTK, SIM1_BASE, &changeTmp, 4);

            // 过寄存器检测
            uint changeTmp = 0x1234;
            uc_mem_write(MTK, 0xA10001D4, ref changeTmp, 4);

            changeTmp = 0x20;
            uc_mem_write(MTK, 0xF018CFE5, ref changeTmp, 1);

            changeTmp = 2;
            uc_mem_write(MTK, 0x81060010, ref changeTmp, 2);

            // 过方法sub_80017C0
            changeTmp = 2;
            uc_mem_write(MTK, 0x8200021C, ref changeTmp, 4);

            changeTmp = 0x3FFFFFFU << 16;
            uc_mem_write(MTK, 0x82000224, ref changeTmp, 4);

            changeTmp = 660;
            uc_mem_write(MTK, 0x82000228, ref changeTmp, 4);

            // 模拟按键开机启动
            SimulatePressKey(0x17, 1);

            uint changeTmp1 = 0x26409001; // 开启memory dump
            uc_mem_write(MTK, 0xF016AD20, ref changeTmp1, 4);

            // SRAM开始的320字节(0x140)内存要保留
            changeTmp = 3;
            uc_mem_write(MTK, 0x81000040, ref changeTmp, 4);

            // 过sub_819E8EC方法
            uint unk_data = 0x20;
            uc_mem_write(MTK, UART_LINE_STATUS_REG, ref unk_data, 4);

            // 过sub_8000D9C方法
            unk_data = 25168;
            uc_mem_write(MTK, 0x80010008, ref unk_data, 4);

            // 过sub_8703796方法
            unk_data = 2;
            uc_mem_write(MTK, 0x08000AD4, ref unk_data, 2);
            // 还原Flash数据
            int flashDataSize = 0;
            // if (readFile("Rom\\flash.lock", &flashDataSize) && flashDataSize > 0)
            // {
            //    char *flashDataTmp = readFile(FLASH_IMG_PATH, &flashDataSize);
            //    uc_mem_write(MTK,0x8780000, flashDataTmp, size_4mb);
            // }

            try
            {
                    // 开始模拟执行
                 MTK.EmuStart(startAddress, startAddress + 1, 0, 0);

            }catch(Exception ex)
            {
                // 错误处理
                Console.WriteLine("Exception:" + ex.ToString());
            }

            //switch (p)
            //{
            //    case UcErr.UC_ERR_READ_UNMAPPED:
            //        Console.WriteLine("模拟错误：此处内存不可读");
            //        break;
            //    case UcErr.UC_ERR_WRITE_UNMAPPED:
            //        Console.WriteLine("模拟错误：此处内存不可写");
            //        break;
            //    case UcErr.UC_ERR_FETCH_UNMAPPED:
            //        Console.WriteLine("模拟错误：此处内存不可执行");
            //        break;
            //    case UcErr.UC_ERR_OK:
            //        break;
            //    default:
            //        Console.WriteLine($"模拟错误：(未处理){uc_strerror(p)}");
            //        break;
            //}

            is_uc_exited = 1;
            DumpCpuInfo();
        }
        /// <summary>
        /// 输出CPU寄存器信息
        /// </summary>
        static void DumpCpuInfo()
        {
            uint r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0;
            uint msp = 0, pc = 0, lr = 0, cpsr = 0;

            // 读取寄存器值
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_PC, ref pc);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_SP, ref msp);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_CPSR, ref cpsr);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_LR, ref lr);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_R0, ref r0);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_R1, ref r1);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_R2, ref r2);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_R3, ref r3);
            uc_reg_readRef(MTK, Arm.UC_ARM_REG_R4, ref r4);

            // 输出寄存器信息
            Console.WriteLine($"r0:{r0:X8} r1:{r1:X8} r2:{r2:X8} r3:{r3:X8} r4:{r4:X8}");

            // 输出状态信息（包含Thumb模式和处理器模式）
            Console.WriteLine($"msp:{msp:X8} cpsr:{cpsr:X8}(thumb:{(cpsr & 0x20) > 0})(mode:{cpsr & 0x1F}) " +
                             $"lr:{lr:X8} pc:{pc:X8} lastPc:{lastAddress:X8} irq_c({irq_nested_count})");

            // 输出SIM设备状态
            Console.WriteLine($"sim_dev(rx_irq:{vm_sim1_dev.IrqEnable & 2:x})");
            Console.WriteLine("------------");
        }

        static int currentTime = 0;

        static int lastCmdFlushTime = 0;
        static int last_timer_interrupt_time = 0;
        static int last_rtc_interrupt_time = 0;
        static int last_sim_interrupt_time = 0;

        /// <summary>
        /// 屏幕渲染线程
        /// </summary>
        public static void ScreenRenderThread()
        {
            while (true)
            {
                currentTime = Environment.TickCount;
                RenderGdiBufferToWindow();

                // 控制台输出刷新
                if (currentTime > lastCmdFlushTime)
                {
                    lastCmdFlushTime = currentTime + 100;
                    Console.Out.Flush();
                }

                // 定时器中断处理
                if (currentTime > last_timer_interrupt_time)
                {
                    last_timer_interrupt_time = currentTime + interruptPeroidms;
                    EnqueueVMEvent(VM_EVENT.VM_EVENT_Timer_IRQ, 0, 0);
                }
                // RTC中断处理
                else if (currentTime > last_rtc_interrupt_time)
                {
                    last_rtc_interrupt_time = currentTime + 500;
                    EnqueueVMEvent(VM_EVENT.VM_EVENT_RTC_IRQ, 0, 0);
                }
                // SIM卡中断处理
                else if (currentTime > last_sim_interrupt_time)
                {
                    last_sim_interrupt_time = currentTime + interruptPeroidms;

                    if (irq_nested_count == 0)
                    {
                        // SIM1中断检查
                        if ((vm_sim1_dev.IrqEnable & (uint)vm_sim1_dev.IrqChannel) != 0 && vm_sim1_dev.IrqStart)
                        {
                            vm_sim1_dev.IrqStart = false;
                            EnqueueVMEvent(VM_EVENT.VM_EVENT_SIM_IRQ, (uint)vm_sim1_dev.IrqChannel, 0);
                        }
                        // SIM2中断检查
                        else if ((vm_sim2_dev.IrqEnable & (uint)vm_sim2_dev.IrqChannel) != 0 && vm_sim2_dev.IrqStart)
                        {
                            vm_sim2_dev.IrqStart = false;
                            EnqueueVMEvent(VM_EVENT.VM_EVENT_SIM_IRQ, (uint)vm_sim2_dev.IrqChannel, 1);
                        }
                        // SIM1 DMA处理
                        else if (vm_dma_sim1_config.ConfigFinish == 1)
                        {
                            vm_dma_sim1_config.ConfigFinish = 0;
                            if (vm_dma_sim1_config.Direction == DMA_DATA_DIRECTION.DMA_DATA_RAM_TO_REG)
                            {
                                EnqueueVMEvent(VM_EVENT.VM_EVENT_SIM_T0_TX_END, 0, 0);
                            }
                            else
                            {
                                EnqueueVMEvent(VM_EVENT.VM_EVENT_SIM_T0_RX_END, 0, 0);
                            }
                        }
                        // SIM2 DMA处理
                        else if (vm_dma_sim2_config.ConfigFinish == 1)
                        {
                            vm_dma_sim2_config.ConfigFinish = 0;
                            if (vm_dma_sim2_config.Direction == DMA_DATA_DIRECTION.DMA_DATA_RAM_TO_REG)
                            {
                                EnqueueVMEvent(VM_EVENT.VM_EVENT_SIM_T0_TX_END, 1, 0);
                            }
                            else
                            {
                                EnqueueVMEvent(VM_EVENT.VM_EVENT_SIM_T0_RX_END, 1, 0);
                            }
                        }
                    }
                }

                Thread.Sleep(1); // 1ms延迟
            }
        }

        /// <summary>
        /// 更新图像的委托
        /// </summary>
        public static Action<byte[][]> UpdateSurfaceAction;

        static byte[] screenBuffer = new byte[LCD_SCREEN_WIDTH * LCD_SCREEN_HEIGHT * 2];

        public static void RenderGdiBufferToWindow()
        {
            // Get window surface
            // IntPtr screenSurface = SDL.SDL_GetWindowSurface(window);

            if (lcdUpdateFlag)
            {
                // Create a Bitmap to hold our PNG
                //using (Bitmap bmp = new Bitmap(LCD_SCREEN_WIDTH, LCD_SCREEN_HEIGHT, PixelFormat.Format32bppArgb))
                //{
                byte[][] datas = new byte[4][]; 
                    for (byte li = 0; li < 4; li++)
                    {
                        uint pz = LCD_Layer_Address[li];
                        if (pz > 0)
                        {
                        // Read screen buffer from emulated memory 
                        screenBuffer=  MTK.MemRead(pz, LCD_SCREEN_WIDTH * LCD_SCREEN_HEIGHT * 2);
                        datas[li] = screenBuffer;
                    //// Lock bitmap data for direct access
                    //BitmapData bmpData = bmp.LockBits(
                    //    new Rectangle(0, 0, bmp.Width, bmp.Height),
                    //    ImageLockMode.WriteOnly,
                    //    bmp.PixelFormat);

                    //    byte[] ptr = new byte[bmpData.Stride * bmpData.Height]; 
                    //    Marshal.Copy(bmpData.Scan0, ptr, 0, ptr.Length);  
                    //    for (ushort i = 0; i < LCD_SCREEN_HEIGHT; i++)
                    //        {
                    //            for (ushort j = 0; j < LCD_SCREEN_WIDTH; j++)
                    //            {
                    //                pz = (uint)(j + i * LCD_SCREEN_WIDTH);
                    //                ushort color = BitConverter.ToUInt16(screenBuffer, (int)pz * 2);
                    //                if (color != 0x1f)
                    //                {
                    //                    // Convert 565 RGB to 888 RGB
                    //                    byte r = (byte)((color >> 11) & 0x1F);
                    //                    byte g = (byte)((color >> 5) & 0x3F);
                    //                    byte b = (byte)(color & 0x1F);

                    //                    // Scale to 8-bit
                    //                    r = (byte)(r * 255 / 31);
                    //                    g = (byte)(g * 255 / 63);
                    //                    b = (byte)(b * 255 / 31);

                    //                    // Set pixel (BGRA format)
                    //                    int pos = (i * bmpData.Stride) + (j * 4);
                    //                    ptr[pos] = b;     // Blue
                    //                    ptr[pos + 1] = g;  // Green
                    //                    ptr[pos + 2] = r;  // Red
                    //                    ptr[pos + 3] = 255; // Alpha (fully opaque)
                    //                }
                    //            }
                    //        }
                    //        //byte[] datas = PointerToByteArray(ptr, LCD_SCREEN_WIDTH * LCD_SCREEN_HEIGHT * 2);  
                    //          Marshal.Copy(ptr, 0, bmpData.Scan0, ptr.Length);
                    //        bmp.UnlockBits(bmpData);

                    //   }
                    }

                    UpdateSurfaceAction?.Invoke(datas);
                }

                lcdUpdateFlag = false;
            }

        }
        
        static int debugType = 0;

        public static void MouseEvent(int type, int data0, int data1)
        {
            //    uc_mem_read(MTK, 0x4000AD38, ref changeTmp, 4);
            //    uc_mem_read(MTK, 0x4000AD30, ref changeTmp1, 4);
            //    Console.WriteLine("[SDL](TMD_STATE:{0:x},TMD_Time_Slice:{1:x})", changeTmp, changeTmp1);
            /*
                if (!hasISR)
                {
                    isrStack[0] = 0xF01D283C;
                    isrStack[1] = 1;
                    isrStack[2] = 0;
                    isrStack[4] = 0;
                    ISR_Start_Address = 0x823f7b7;
                    ISR_End_Address = 0x823F7D8;
                    requireSetIsrStack = true;
                    hasISR = true;
                }
                */
            // Update_RTC_Time();
            uc_mem_read(MTK, 0x4000ad10, ref changeTmp1, 4);
            uc_mem_read(MTK, changeTmp1, ref changeTmp2, 4);
            uc_mem_read(MTK, changeTmp1 + 20, ref changeTmp1, 4);
            Console.WriteLine("AC_TM_L({0:x})({1:x})({2:x})", changeTmp1, changeTmp2, changeTmp3);
            uc_mem_read(MTK, 0x4000ad28, ref changeTmp2, 4);
            uc_mem_read(MTK, 0x4000ad2c, ref changeTmp3, 4);
            Console.WriteLine("TMD_Timer_State({0:x}),TMD_Timer({1:x})", changeTmp3, changeTmp2);
            debugType = 10;
            DumpCpuInfo();
        }
    }
}
