using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MtkSimalatorSharp.backend
{
    public class Cpsr
    {
        private readonly IBackend backend;
        private readonly int regId;
        private int value;

        private Cpsr(IBackend backend, int regId)
        {
            this.backend = backend;
            this.regId = regId;
            this.value = (int)backend.RegRead(regId);
        }

        public static Cpsr GetArm(IBackend backend)
        {
            return new Cpsr(backend, Arm.UC_ARM_REG_CPSR);
        }

        //public static Cpsr GetArm64(Backend backend)
        //{
        //    return new Cpsr(backend, Arm.UC_ARM64_REG_NZCV);
        //}

        private static bool HasBit(int value, int offset)
        {
            return ((value >> offset) & 1) == 1;
        }

        private void SetBit(int offset)
        {
            int mask = 1 << offset;
            value |= mask;
            backend.RegWrite(regId, value);
        }

        private void ClearBit(int offset)
        {
            int mask = ~(1 << offset);
            value &= mask;
            backend.RegWrite(regId, value);
        }

        public int Value => value;

        private const int A32_BIT = 4;
        public bool IsA32() => HasBit(value, A32_BIT);

        private const int THUMB_BIT = 5;
        public bool IsThumb() => HasBit(value, THUMB_BIT);

        private const int NEGATIVE_BIT = 31;
        public bool IsNegative() => HasBit(value, NEGATIVE_BIT);

        internal void SetNegative(bool on)
        {
            if (on) SetBit(NEGATIVE_BIT);
            else ClearBit(NEGATIVE_BIT);
        }

        private const int ZERO_BIT = 30;
        public bool IsZero() => HasBit(value, ZERO_BIT);

        internal void SetZero(bool on)
        {
            if (on) SetBit(ZERO_BIT);
            else ClearBit(ZERO_BIT);
        }

        private const int CARRY_BIT = 29;
        public bool HasCarry() => HasBit(value, CARRY_BIT);

        public void SetCarry(bool on)
        {
            if (on) SetBit(CARRY_BIT);
            else ClearBit(CARRY_BIT);
        }

        private const int OVERFLOW_BIT = 28;
        public bool IsOverflow() => HasBit(value, OVERFLOW_BIT);

        internal void SetOverflow(bool on)
        {
            if (on) SetBit(OVERFLOW_BIT);
            else ClearBit(OVERFLOW_BIT);
        }

        private const int MODE_MASK = 0x1f;
        public int GetMode() => value & MODE_MASK;

        public int GetEL() => (value >> 2) & 3;

        public void SwitchUserMode()
        {
            value &= ~MODE_MASK;
            value |= USR_MODE;
            backend.RegWrite(regId, value);
        } 
        /**
         * 用户模式
         */
        int USR_MODE = 0b10000;

    }
} 