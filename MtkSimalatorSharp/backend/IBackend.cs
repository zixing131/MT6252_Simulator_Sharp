using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;


namespace MtkSimalatorSharp.backend
{
    public interface IBackend
    {

        void OnInitialize();

        void SwitchUserMode();
        void EnableVFP();

        long RegRead(int regId);

        byte[] RegReadVector(int regId);
        void RegWriteVector(int regId, byte[] vector);

        void RegWrite(int regId, long value);

        byte[] MemRead(long address, long size);

        void MemWrite(long address, byte[] bytes);

        void MemMap(long address, long size, int perms);

        void MemProtect(long address, long size, int perms);

        void MemUnmap(long address, long size);

        BreakPoint AddBreakPoint(long address, NativeBreakPointCallback callback, bool thumb);
        bool RemoveBreakPoint(long address);
        void SetSingleStep(int singleStep);
        void SetFastDebug(bool fastDebug);

        void RemoveJitCodeCache(long begin, long end);

        void HookAddNewCodeHook(NativeCodeHook callback, object userData, long begin, long end);

        void DebuggerAddDebugHook(NativeDebugHook callback, object userData, long begin, long end);

        void HookAddNewReadHook(NativeReadHook callback, object userData, long begin, long end);

        void HookAddNewWriteHook(NativeWriteHook callback, object userData, long begin, long end);

        void HookAddNewEventMemHook(NativeEventMemHook callback, int type, object userData);

        void HookAddNewInterruptHook(NativeInterruptHook callback, object userData);

        void HookAddNewBlockHook(NativeBlockHook callback, object userData, long begin, long end);

        void EmuStart(long begin, long until, long timeout, long count);

        void EmuStop();

        void Destroy();

        void ContextRestore(long context);
        void ContextSave(long context);
        long ContextAlloc();
        void ContextFree(long context);

        int GetPageSize();

        void RegisterEmuCountHook(long emuCount);
        void nativeInitialize(int arch, int mode);

        ///**
        //  * 当断点被触发时回调
        //  * @return 返回<code>false</code>表示断点成功，返回<code>true</code>表示不触发断点，继续进行
        //  */
        delegate bool NativeBreakPointCallback(IBackend emulator, long address);

        //delegate void CodeHook(IBackend backend, long address, int size, object user);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate void NativeDebugHook(IBackend backend, long address, int size, object user);
        //delegate void ReadHook(IBackend backend, long address, int size, object user);
        //delegate void WriteHook(IBackend backend, long address, int size, long value, object user);
        //delegate bool EventMemHook(IBackend backend,long address, int size, long value, object user, int unmappedType);

        //delegate void InterruptHook(IBackend backend, int intno, int swi, object user);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void NativeCodeHook(IBackend uc, long address, int size, object user_data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void NativeReadHook(IBackend uc, long address, int size, object user_data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void NativeWriteHook(IBackend uc, long address, int size, long value, object user_data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]  
        public delegate bool NativeEventMemHook(IBackend backend, int type, long address, int size, long value, object userdata);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void NativeInterruptHook(IBackend uc, int intno, object user_data);

        //[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        //public delegate void CodeHookCallback(IntPtr uc, ulong address, uint size, IntPtr user_data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void NativeBlockHook(IBackend uc, long addresslong, int size, object user_data);
         
        //private struct NativeHookWrapper
        //{
        //    public IntPtr HookRef;
        //    public IntPtr UnicornRef;
        //    public IntPtr CallbackPtr;
        //}

    }

    public class BreakPoint
    {
        //public interface BreakPoint
        //{

        //    boolean isTemporary();
        //    void setTemporary(boolean temporary);
        //    BreakPointCallback getCallback();
        //    boolean isThumb();

        //}
        private long address;
        private IBackend.NativeBreakPointCallback callback;

        public BreakPoint(long address, IBackend.NativeBreakPointCallback callback)
        {
            this.address = address;
            this.callback = callback;
        }
    }

    class HookManager
    {
        private readonly Dictionary<IntPtr, object> _activeHooks = new();
        private readonly object _lock = new();

        public IntPtr RegisterHook<T>(T callback, object userData, Delegate nativeDelegate)
        {
            var ptr = Marshal.GetFunctionPointerForDelegate(nativeDelegate);

            lock (_lock)
            {
                _activeHooks[ptr] = Tuple.Create(callback, userData, nativeDelegate);
            }

            return ptr;
        }

        public bool UnregisterHook(IntPtr hookPtr)
        {
            lock (_lock)
            {
                return _activeHooks.Remove(hookPtr);
            }
        }

        public void ClearAllHooks()
        {
            lock (_lock)
            {
                _activeHooks.Clear();
            }
        } 
    }
}