using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MT6252_Simulator_Sharp
{
    class TestJni
    {
        [DllImport("dynarmic.dll", EntryPoint = "Java_com_github_unidbg_arm_backend_unicorn_Unicorn_addBreakPoint", CallingConvention = CallingConvention.StdCall)]
        public static extern void AddBreakPoint(IntPtr env, IntPtr obj, long address);

        [DllImport("dynarmic.dll")]
        public static extern long Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_nativeInitialize(
                          IntPtr env,
                          IntPtr clazz,
                          [MarshalAs(UnmanagedType.U1)] bool flag
                      );

    }
}
