using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MT6252_Simulator_Sharp.MtkSimalator
{

    public struct VM_SIM_DEV
    {
        public SIM_DEV_EVENT Event;           // 事件类型
        public bool IrqStart;                 // 是否启动中断
        public byte IsRst;                    // 复位标志
        public byte RxFinish;                 // 接收完成标志
        public SIM_IRQ_CHANNEL IrqChannel;    // 中断通道
        public uint IrqEnable;                // 中断使能
        public uint Control;                  // 控制寄存器

        public byte[] RxBuffer;               // 1KB 接收缓存
        public byte RxRemainCount;            // 剩余接收字节数
        public byte RxBufferIndex;            // 接收字节下标
        public uint RxCurrentIndex;           // 本次命令接收字节下标

        public byte[] TxBuffer;               // 1KB 发送缓存
        public byte TxBufferIndex;            // 发送字节下标
        public byte[] T0RxData;               // T0 接收数据
        public uint T0TxCount;                // T0 发送字节数
        public uint RxTriggerCount;           // 接收触发计数
        public uint TxTriggerCount;           // 发送触发计数

        // 构造函数，初始化数组
        public VM_SIM_DEV(bool initializeArrays)
        {
            Event = SIM_DEV_EVENT.SIM_DEV_EVENT_NONE;
            IrqStart = false;
            IsRst = 0;
            RxFinish = 0;
            IrqChannel = SIM_IRQ_CHANNEL.SIM_IRQ_NONE;
            IrqEnable = 0;
            Control = 0;

            RxBuffer = new byte[1024];        // 1KB 接收缓存
            RxRemainCount = 0;
            RxBufferIndex = 0;
            RxCurrentIndex = 0;

            TxBuffer = new byte[1024];        // 1KB 发送缓存
            TxBufferIndex = 0;
            T0RxData = new byte[512];         // T0 接收数据
            T0TxCount = 0;
            RxTriggerCount = 0;
            TxTriggerCount = 0;
        }
    }

    public enum SIM_DEV_EVENT
    {
        SIM_DEV_EVENT_NONE,
        SIM_DEV_EVENT_DEBUG,
        SIM_DEV_EVENT_DEBUG_N,
        SIM_DEV_EVENT_ATR_PRE,
        SIM_DEV_EVENT_ATR_CIRCLE_DATA,
        SIM_DEV_EVENT_NOATR,
        SIM_DEV_EVENT_ATR,
        SIM_DEV_EVENT_PTS,
        SIM_DEV_EVENT_CMD
    }

    public enum SIM_IRQ_CHANNEL
    {
        SIM_IRQ_NONE = 0,
        SIM_IRQ_RX = 2,
        SIM_IRQ_TX = 1,
        SIM_IRQ_RXERR = 0x100,
        SIM_IRQ_TOUT = 8,
        SIM_IRQ_T0END = 0x80,
        SIM_IRQ_NOATR = 0x20,
        SIM_IRQEN_CMDDMANormal = 0x19c,
        SIM_IRQEN_CMDNormal = 0x19e,
        SIM_IRQ_EDCERR = 0x400,
        SIM_IRQ_T1END = 0x200,
        SIM_IRQ_DMA_CMD = 0x800
    }

    public struct SerialFlash_Control
    {
        public byte[] SR_REG;          // Size 3
        public byte cmd;
        public uint address;
        public byte cmdRev;            // 1 = command received
        public uint sendDataCount;
        public uint readDataCount;
        public uint[] cacheData;       // Size 64
    }


    public enum DMA_MASTER_CHANEL
    {
        SIM,
        MSDC,
        UNK1,
        UNK2,
        USB1_TX,
        USB1_RX,
        USB2_TX,
        USB2_RX,
        UART1_RX,
        UART1_TX,
        UART2_RX,
        UART2_TX,
        UART3_RX,
        UART3_TX,
        DSP,
        UNK3,
        UNK4,
        I2C_TX,
        I2C_RX,
        SIM2,
        DSP2
    }

    public enum DMA_DATA_DIRECTION
    {
        DMA_DATA_RAM_TO_REG,
        DMA_DATA_REG_TO_RAM
    }

    public enum DMA_DATA_BYTE_ALIGN
    {
        DMA_DATA_BYTE_ALIGN_ONE,
        DMA_DATA_BYTE_ALIGN_TWO,
        DMA_DATA_BYTE_ALIGN_FOUR
    }

    public struct VM_DMA_CONFIG
    {
        public uint Control;                          // 控制寄存器
        public DMA_MASTER_CHANEL Chanel;            // DMA 主通道
        public DMA_DATA_DIRECTION Direction;        // 数据传输方向
        public DMA_DATA_BYTE_ALIGN Align;           // 数据对齐方式
        public uint DataAddr;                        // 数据地址
        public uint TransferCount;                   // 传输字节数
        public uint ConfigFinish;                    // 配置完成标志
        public uint TransferEndInterruptEnable;      // 传输结束中断使能
        public byte[] CacheBuffer;                  // 4KB 缓存

        // 构造函数，初始化数组
        public VM_DMA_CONFIG(bool initializeArrays)
        {
            Control = 0;
            Chanel = DMA_MASTER_CHANEL.SIM;
            Direction = DMA_DATA_DIRECTION.DMA_DATA_RAM_TO_REG;
            Align = DMA_DATA_BYTE_ALIGN.DMA_DATA_BYTE_ALIGN_ONE;
            DataAddr = 0;
            TransferCount = 0;
            ConfigFinish = 0;
            TransferEndInterruptEnable = 0;
            CacheBuffer = new byte[4096];            // 4KB 缓存
        }
    }


}
