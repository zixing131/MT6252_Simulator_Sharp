using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks; 
using static MtkSimalatorSharp.backend.IBackend; 

namespace MtkSimalatorSharp.backend
{
    public class UnicornNative :IBackend
    {
        UIntPtr[] _eng;
        public unsafe void nativeInitialize(int arch, int mode)
        {
            _disposablePointers = new List<IntPtr>();
            _eng = new UIntPtr[]
            {
                new UIntPtr(this.allocate(IntPtr.Size))
            };
            uc_open((uint)arch, (uint)mode,_eng);

            // this.SwitchUserMode();
            // this.EnableVFP(); 
        }

        internal unsafe void* allocate(int size)
        {
            IntPtr intPtr = Marshal.AllocHGlobal(size);
            _disposablePointers.Add(intPtr);
            return intPtr.ToPointer(); 
        }

        internal List<IntPtr> _disposablePointers;


        public BreakPoint AddBreakPoint(long address, IBackend.NativeBreakPointCallback callback, bool thumb)
        {

            throw new NotImplementedException("AddBreakPoint not implemented");
        }

        public long ContextAlloc()
        {
            return 0;
        }

        public void ContextFree(long context)
        {

        }

        public void ContextRestore(long context)
        {

        }

        public void ContextSave(long context)
        {

        }

        public void DebuggerAddDebugHook(IDebugHook callback, object userData, long begin, long end)
        {

        }

        public void Destroy()
        {

        }

        public void EmuStart(long begin, long until, long timeout, long count)
        {
            uc_emu_start(_eng[0], (ulong)begin, (ulong)until, (ulong)timeout, (ulong)count);
        }

        public void EmuStop()
        {
            uc_emu_stop(_eng[0]);
        }

        public void EnableVFP()
        {
            // 具体实现取决于Unicorn的API 
            long value = RegRead(Arm.UC_ARM_REG_C1_C0_2);
            value |= (0xf << 20);
            RegWrite(Arm.UC_ARM_REG_C1_C0_2, value);
            RegWrite(Arm.UC_ARM_REG_FPEXC, 0x40000000);
        }

        public int GetPageSize()
        {
            // 通常为4096，但可以查询系统或Unicorn获取实际值
            return 4096;
        }


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] 
        [Serializable]

        internal delegate void CodeHookInternal(IntPtr a, long b, int c, IntPtr d);

        internal static List<Tuple<ICodeHook, Tuple<IntPtr, object, object>>> _codeHooks = new List<Tuple<ICodeHook, Tuple<nint, object, object>>>();

        [Serializable]
        [StructLayout(LayoutKind.Auto, CharSet = CharSet.Auto)]
        internal sealed class codeHookInternal_155
        {
            public codeHookInternal_155(IBackend @this, ICodeHook callback, object userData)
            {
                this.@this = @this;
                this.callback = callback;
                this.userData = userData;
            }
            
            internal void Invoke(IntPtr delegateArg0, long delegateArg1, int delegateArg2, IntPtr delegateArg3)
            {
                this.callback.hook(this.@this, delegateArg1, delegateArg2, this.userData);
            }

            public IBackend @this;

            public ICodeHook callback;

            public object userData;
        }

        public unsafe void HookAddNewCodeHook(ICodeHook callback, object userData, long begin, long end)
        {
            CodeHookInternal codeHookInternal = new CodeHookInternal(new codeHookInternal_155(this, callback, userData).Invoke);
            IntPtr functionPointerForDelegate = Marshal.GetFunctionPointerForDelegate(codeHookInternal);
            IntPtr uintPtr = new IntPtr(this.allocate(IntPtr.Size));
            var errcode = uc_hook_add_noarg(_eng[0], uintPtr, 4, new UIntPtr(functionPointerForDelegate.ToPointer()), IntPtr.Zero, (ulong)begin, (ulong)end);
            if (errcode == 0 )
            {
                IntPtr uintPtr2 = Marshal.ReadIntPtr(uintPtr);
                _codeHooks.Add(new Tuple< ICodeHook, Tuple<IntPtr, object, object>>(callback, new Tuple<IntPtr, object, object>(uintPtr2, userData, codeHookInternal)));
                return;
            }
            throw new Exception("HookAddNewCodeHook Exception");
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [Serializable]

        internal delegate void ReadHookInternal(IntPtr delegateArg0, int delegateArg1, long delegateArg2, int delegateArg3, IntPtr delegateArg4);

        internal static List<Tuple<IReadHook, Tuple<IntPtr, object, object>>> _ReadHooks = new List<Tuple<IReadHook, Tuple<nint, object, object>>>();

        [Serializable]
        [StructLayout(LayoutKind.Auto, CharSet = CharSet.Auto)]
        internal sealed class ReadHookInternal_155
        {
            public ReadHookInternal_155(IBackend @this, IReadHook callback,  object userData)
            {
                this.@this = @this;
                this.callback = callback;
                this.userData = userData; 

            }

            internal void Invoke(IntPtr delegateArg0, int delegateArg1, long delegateArg2, int delegateArg3, IntPtr delegateArg4)
            {
                this.callback.hook(this.@this, delegateArg2, delegateArg3, this.userData);
            }

            public IBackend @this;

            public IReadHook callback;

            public object userData;
            public long address;
            public int size;
            public long value;
        } 

        public unsafe void HookAddNewReadHook(IReadHook callback, object userData, long begin, long end)
        {
            ReadHookInternal ReadHookInternal = new ReadHookInternal(new ReadHookInternal_155(this, callback, userData).Invoke);
            IntPtr functionPointerForDelegate = Marshal.GetFunctionPointerForDelegate(ReadHookInternal);
            IntPtr uintPtr = new IntPtr(this.allocate(IntPtr.Size));
            var errcode = uc_hook_add_noarg(_eng[0], uintPtr, 1024, new UIntPtr(functionPointerForDelegate.ToPointer()), IntPtr.Zero, (ulong)begin, (ulong)end);
            if (errcode == 0)
            {
                IntPtr uintPtr2 = Marshal.ReadIntPtr(uintPtr);
                _ReadHooks.Add(new Tuple< IReadHook, Tuple<IntPtr, object, object>>(callback, new Tuple<IntPtr, object, object>(uintPtr2, userData, ReadHookInternal)));
                return;
            }
        }
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [Serializable]

        internal delegate void BlockHookInternal(IntPtr delegateArg0, long delegateArg1, int delegateArg2, IntPtr delegateArg3);

        internal static List<Tuple<IBlockHook, Tuple<IntPtr, object, object>>> _BlockHooks = new List<Tuple<IBlockHook, Tuple<nint, object, object>>>();

        [Serializable]
        [StructLayout(LayoutKind.Auto, CharSet = CharSet.Auto)]
        internal sealed class BlockHookInternal_155
        {
            public BlockHookInternal_155(IBackend @this, IBlockHook callback, object userData)
            {
                this.@this = @this;
                this.callback = callback;
                this.userData = userData;

            }

            internal void Invoke(IntPtr delegateArg0, long delegateArg1, int delegateArg2, IntPtr delegateArg3)
            {
                this.callback.hook(this.@this, delegateArg1, delegateArg2, this.userData);
            }

            public IBackend @this; 
            public IBlockHook callback; 
            public object userData; 
        }

        public unsafe void HookAddNewBlockHook(IBlockHook callback, object userData, long begin, long end)
        {
            BlockHookInternal BlockHookInternal = new BlockHookInternal(new BlockHookInternal_155(this, callback, userData).Invoke);
            IntPtr functionPointerForDelegate = Marshal.GetFunctionPointerForDelegate(BlockHookInternal);
            IntPtr uintPtr = new IntPtr(this.allocate(IntPtr.Size));
            var errcode = uc_hook_add_noarg(_eng[0], uintPtr, 8, new UIntPtr(functionPointerForDelegate.ToPointer()), IntPtr.Zero, (ulong)begin, (ulong)end);
            if (errcode == 0)
            {
                IntPtr uintPtr2 = Marshal.ReadIntPtr(uintPtr);
                _BlockHooks.Add(new Tuple<IBlockHook, Tuple<IntPtr, object, object>>(callback, new Tuple<IntPtr, object, object>(uintPtr2, userData, BlockHookInternal)));
                return;
            }
            throw new Exception("HookAddNewBlockHook Exception");
        }


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [Serializable]

        internal delegate void WriteHookInternal(IntPtr delegateArg0, int delegateArg1, long delegateArg2, int delegateArg3, long delegateArg4, IntPtr delegateArg5);

        internal static List<Tuple<IWriteHook, Tuple<IntPtr, object, object>>> _WriteHooks=new List<Tuple<IWriteHook, Tuple<nint, object, object>>>();

        [Serializable]
        [StructLayout(LayoutKind.Auto, CharSet = CharSet.Auto)]
        internal sealed class WriteHookInternal_155
        {
            public WriteHookInternal_155(IBackend @this, IWriteHook callback, object userData)
            {
                this.@this = @this;
                this.callback = callback;
                this.userData = userData;

            }

            internal void Invoke(IntPtr delegateArg0, int delegateArg1, long delegateArg2, int delegateArg3, long delegateArg4, IntPtr delegateArg5)
            {
                this.callback.hook(this.@this, delegateArg2, delegateArg3, delegateArg4, this.userData);
            }

            public IBackend @this;

            public IWriteHook callback;

            public object userData;
            public long address;
            public int size;
            public long value;
        }

        public unsafe void HookAddNewWriteHook(IWriteHook callback, object userData, long begin, long end)
        {
            WriteHookInternal WriteHookInternal = new WriteHookInternal(new WriteHookInternal_155(this, callback, userData).Invoke);
            IntPtr functionPointerForDelegate = Marshal.GetFunctionPointerForDelegate(WriteHookInternal);
            IntPtr uintPtr = new IntPtr(this.allocate(IntPtr.Size));
            var errcode = uc_hook_add_noarg(_eng[0], uintPtr, 2048, new UIntPtr(functionPointerForDelegate.ToPointer()), IntPtr.Zero, (ulong)begin, (ulong)end);
            if (errcode == 0)
            {
                IntPtr uintPtr2 = Marshal.ReadIntPtr(uintPtr);
                _WriteHooks.Add(new Tuple< IWriteHook, Tuple<IntPtr, object, object>>(callback, new Tuple<IntPtr, object, object>(uintPtr2, userData, WriteHookInternal)));
                return;
            }
            throw new Exception("HookAddNewWriteHook Exception");
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [Serializable]

        internal delegate bool EventMemHookInternal(IntPtr delegateArg0, int delegateArg1, long delegateArg2, int delegateArg3, long delegateArg4, IntPtr delegateArg5);

        internal static List<Tuple<IEventMemHook, Tuple<IntPtr, object, object>>> _EventMemHooks=new List<Tuple<IEventMemHook, Tuple<nint, object, object>>>();

        [Serializable]
        [StructLayout(LayoutKind.Auto, CharSet = CharSet.Auto)]
        internal sealed class EventMemHookInternal_155
        {
            public EventMemHookInternal_155(IBackend @this, IEventMemHook callback, object userData)
            {
                this.@this = @this;
                this.callback = callback;
                this.userData = userData;

            } 
            internal bool Invoke(IntPtr delegateArg0, int delegateArg1, long delegateArg2, int delegateArg3, long delegateArg4, IntPtr delegateArg5)
            {
                return this.callback.hook(this.@this, delegateArg2, delegateArg3, delegateArg4, this.userData);
            }
            public IBackend @this;

            public IEventMemHook callback;

            public object userData;
            public long address;
            public int size;
            public long value;
        }

        public unsafe void HookAddNewEventMemHook(IEventMemHook callback, int type, object userData)
        {
            EventMemHookInternal EventMemHookInternal = new EventMemHookInternal(new EventMemHookInternal_155(this, callback, userData).Invoke);
            IntPtr functionPointerForDelegate = Marshal.GetFunctionPointerForDelegate(EventMemHookInternal);
            IntPtr uintPtr = new IntPtr(this.allocate(IntPtr.Size));
            var errcode = uc_hook_add_noarg(_eng[0], uintPtr, 2, new UIntPtr(functionPointerForDelegate.ToPointer()), IntPtr.Zero, 1, 0);
            if (errcode == 0)
            {
                IntPtr uintPtr2 = Marshal.ReadIntPtr(uintPtr);
                _EventMemHooks.Add(new Tuple<IEventMemHook, Tuple<IntPtr, object, object>>(callback, new Tuple<IntPtr, object, object>(uintPtr2, userData, EventMemHookInternal)));
                return;
            }
            throw new Exception("HookAddNewEventMemHook Exception");
        }

        public void HookAddNewInterruptHook(IInterruptHook callback, object userData)
        {
            throw new NotImplementedException("HookAddNewInterruptHook Exception"); 
        }


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        [Serializable]

        internal delegate void InterruptHookInternal(IntPtr delegateArg0, int inno, IntPtr delegateArg3);

        internal static List<Tuple<IBackend.NativeInterruptHook, Tuple<IntPtr, object, object>>> _InterruptHooks = new List<Tuple<NativeInterruptHook, Tuple<nint, object, object>>>();

        [Serializable]
        [StructLayout(LayoutKind.Auto, CharSet = CharSet.Auto)]
        internal sealed class InterruptHookInternal_155
        {
            public InterruptHookInternal_155(IBackend @this, NativeInterruptHook callback, object userData)
            {
                this.@this = @this;
                this.callback = callback;
                this.userData = userData;

            }

            internal void Invoke(IntPtr delegateArg0, int inno, IntPtr delegateArg3)
            {
                this.callback(this.@this, inno, this.userData);
            }

            public IBackend @this;

            public NativeInterruptHook callback;

            public object userData;
            public long address;
            public int size;
            public long value;
        }

        public unsafe void HookAddNewInterruptHook(IBackend.NativeInterruptHook callback, object userData, long begin, long end)
        {
            InterruptHookInternal InterruptHookInternal = new InterruptHookInternal(new InterruptHookInternal_155(this, callback, userData).Invoke);
            IntPtr functionPointerForDelegate = Marshal.GetFunctionPointerForDelegate(InterruptHookInternal);
            IntPtr uintPtr = new IntPtr(this.allocate(IntPtr.Size));
            var errcode = uc_hook_add_noarg(_eng[0], uintPtr, 1, new UIntPtr(functionPointerForDelegate.ToPointer()), IntPtr.Zero, (ulong)begin, (ulong)end);
            if (errcode == 0)
            {
                IntPtr uintPtr2 = Marshal.ReadIntPtr(uintPtr);
                _InterruptHooks.Add(new Tuple<NativeInterruptHook, Tuple<IntPtr, object, object>>(callback, new Tuple<IntPtr, object, object>(uintPtr2, userData, InterruptHookInternal)));
                return;
            }
            throw new Exception("HookAddNewInterruptHook Exception");
        }

        public void MemMap(long address, long size, int perms)
        {
            uc_mem_map(_eng[0],(ulong) address, (UIntPtr)size, (uint)perms);
        }

        public void MemProtect(long address, long size, int perms)
        {

            uc_mem_protect(_eng[0], (ulong)address, (UIntPtr)size, (uint)perms);
        }

        public byte[] MemRead(long address, long size)
        {
            byte[] retdata = new byte[size];
            int ret = uc_mem_read(_eng[0], (ulong)address, retdata,(UIntPtr)size);
            return retdata;
        }

        public void MemUnmap(long address, long size)
        {
            uc_mem_unmap(_eng[0], (ulong)address, (UIntPtr)size); 

        }

        public void MemWrite(long address, byte[] bytes)
        {
            uc_mem_write(_eng[0], (ulong)address, bytes,(UIntPtr)bytes.Length);
        }

        public void OnInitialize()
        {
            // 初始化逻辑已移至构造函数和nativeInitialize方法
        }

        public void RegisterEmuCountHook(long emuCount)
        {

        }

        public long RegRead(int regId)
        {
            byte[] array = new byte[8];
             uc_reg_read(_eng[0], regId, array); 
            return bytesToInt64(array);
        }
        internal static long bytesToInt64(byte[] v)
        {
            ulong num = 0UL;
            for (int i = 0; i < v.Length; i++)
            {
                byte b = (byte)(v[i] & byte.MaxValue);
                ulong num2 = num;
                ulong num3 = (ulong)b;
                int num4 = i * 8;
                num = num2 + (num3 << num4);
            }
            return (long)num;
        }
        internal static byte[] int64ToBytes(long v)
        {
            byte[] array = new byte[8];
            ulong num = (ulong)v;
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = (byte)(num & 255UL);
                num >>= 8;
            }
            return array;
        }

        public byte[] RegReadVector(int regId)
        {
            throw new NotImplementedException("RegReadVector not implemented");
        }

        public void RegWrite(int regId, long value)
        {

            var bytesvalue = int64ToBytes(value);
            uc_reg_write(_eng[0], regId, bytesvalue);

        }

        public void RegWriteVector(int regId, byte[] vector)
        {

        }

        public bool RemoveBreakPoint(long address)
        {

            return false;
        }

        public void RemoveJitCodeCache(long begin, long end)
        {

        }

        public void SetFastDebug(bool fastDebug)
        {

        }

        public void SetSingleStep(int singleStep)
        {

        }

        public void SwitchUserMode()
        {
            // 具体实现取决于Unicorn的API
            Cpsr.GetArm(this).SwitchUserMode();
        }

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_version(UIntPtr major, UIntPtr minor);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_open(uint arch, uint mode, UIntPtr[] engine);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_close(UIntPtr eng);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_mem_map(UIntPtr eng, ulong address, UIntPtr size, uint perm);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_mem_map_ptr(UIntPtr eng, ulong address, UIntPtr size, uint perm, UIntPtr ptr);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_mem_unmap(UIntPtr eng, ulong address, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_mem_protect(UIntPtr eng, ulong address, UIntPtr size, uint perms);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_mem_write(UIntPtr eng, ulong address, byte[] value, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_mem_read(UIntPtr eng, ulong address, byte[] value, UIntPtr size);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_reg_write(UIntPtr eng, int regId, byte[] value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_reg_read(UIntPtr eng, int regId, byte[] value);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_emu_start(UIntPtr eng, ulong beginAddr, ulong untilAddr, ulong timeout, ulong count);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_emu_stop(UIntPtr eng);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_hook_del(UIntPtr eng, UIntPtr hook);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool uc_arch_supported(int arch);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int uc_errno(UIntPtr eng);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr uc_strerror(int err);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")]
        internal static extern int uc_hook_add_noarg(UIntPtr eng, IntPtr hh, int callbackType, UIntPtr callback, IntPtr userData, ulong hookbegin, ulong hookend);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")]
        internal static extern int uc_hook_add_arg0(UIntPtr eng, UIntPtr hh, int callbackType, UIntPtr callback, IntPtr userData, ulong hookbegin, ulong hookend, int arg0);

        [DllImport("unicorn", CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")]
        internal static extern int uc_hook_add_arg0_arg1(UIntPtr eng, UIntPtr hh, int callbackType, UIntPtr callback, IntPtr userData, ulong hookbegin, ulong hookend, ulong arg0, ulong arg1);
    }
}
