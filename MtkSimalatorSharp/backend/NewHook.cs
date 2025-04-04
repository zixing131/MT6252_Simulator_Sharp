using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks; 

namespace MtkSimalatorSharp.backend
{
    public interface IHook
    {

    }

    public interface IBlockHook : IHook
    {
        void hook(IBackend uc, long address, int size, object user);
    }
    public interface ICodeHook : IHook
    {

        void hook(IBackend u, long address, int size, object user);

    }

    public interface IDebugHook : ICodeHook
    {

        void onBreak(IBackend u, long address, int size, object user);

    }
    public interface IReadHook : IHook
    {

        void hook(IBackend u, long address, int size, object user);

    }
    public interface IWriteHook : IHook
    {
        void hook(IBackend u, long address, int size, long value, object user);

    }

    public interface IInterruptHook : IHook
    {
        void hook(IBackend u, int intno, object user); 
    }

    public interface IEventMemHook : IHook
    { 
        bool hook(IBackend u, long address, int size, long value, object user); 
    }

    public class NewHook
    {
        IHook function;
        public object data;
        public IBackend uc;
        public NewHook(IHook f, object userdata, IBackend uc)
        {
            function = f;
            data = userdata;
            this.uc = uc;
        }

        /**
         * for UC_HOOK_BLOCK
         */
        public void onBlock(long address, int size)
        {
            IBlockHook hook = (IBlockHook)function;
            hook.hook(uc, address, size, data);
        }

        /**
         * for UC_HOOK_CODE
         */
        public void onCode(long address, int size)
        {
            ICodeHook hook = (ICodeHook)function;
            hook.hook(uc, address, size, data);
        }

        /**
         * on breakpoint hit
         */
        public void onBreak(long address, int size)
        {
            IDebugHook hook = (IDebugHook)function;
            hook.onBreak(uc, address, size, data);
        }

        /**
         * for UC_HOOK_MEM_READ
         */
        public void onRead(long address, int size)
        {
            IReadHook hook = (IReadHook)function;
            hook.hook(uc, address, size, data);
        }

        /**
         * for UC_HOOK_MEM_WRITE
         */
        public void onWrite(long address, int size, long value)
        {
            IWriteHook hook = (IWriteHook)function;
            hook.hook(uc, address, size, value, data);
        }

        /**
         * for UC_HOOK_INTR
         */
        public void onInterrupt(int intno)
        {
            IInterruptHook hook = (IInterruptHook)function;
            hook.hook(uc, intno, data);
        }

        /**
         * for UC_HOOK_MEM_*
         */
        public bool onMemEvent(int type, long address, int size, long value)
        {
            IEventMemHook hook = (IEventMemHook)function;
            return hook.hook(uc, address, size, value, data);
        } 
    }
}