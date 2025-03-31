using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MT6252_Simulator_Sharp.MtkSimalator
{
    public class VmEvent
    {
        public VM_EVENT Event { get; set; }
        public uint R0 { get; set; }
        public uint R1 { get; set; }
    }
}
