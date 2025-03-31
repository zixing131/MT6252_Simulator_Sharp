using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MT6252_Simulator_Sharp.MtkSimalator
{
    public enum VM_EVENT
    {
        VM_EVENT_NONE,
        VM_EVENT_KEYBOARD,
        VM_EVENT_Timer_IRQ,
        VM_EVENT_MSDC_IO_OK,
        VM_EVENT_MSDC_IO_CALLBACK,
        VM_EVENT_RTC_IRQ,
        VM_EVENT_GPT_IRQ,
        VM_EVENT_SIM_IRQ,
        VM_EVENT_SIM_T0_TX_END,
        VM_EVENT_SIM_T0_RX_END,
        VM_EVENT_DMA_IRQ,
        VM_EVENT_MSDC_IRQ
    }

}
