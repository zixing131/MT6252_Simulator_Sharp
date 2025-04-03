using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MtkSimalatorSharp.backend
{
    public class Common
    {
       public const int UC_ARCH_ARM = 1;
        public const int UC_ARCH_ARM64 = 2;
        public const int UC_MODE_ARM = 0;
        public const int UC_PROT_ALL = 7;
        public const int UC_HOOK_MEM_READ_UNMAPPED = 16;
        public const int UC_HOOK_MEM_WRITE_UNMAPPED = 32;
        public const int UC_HOOK_MEM_FETCH_UNMAPPED = 64;
    }
}
