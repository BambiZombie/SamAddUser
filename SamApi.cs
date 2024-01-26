using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using static SAMRPCNative.SAMEnums;
using static SAMRPCNative.SAMStructs;

namespace SAMRPCNative
{
    public static class SAMStructs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct UnicodeString : IDisposable
        {
            public readonly ushort Length;
            public readonly ushort MaximumLength;
            public IntPtr Buffer;

            public UnicodeString(string s)
                : this()
            {
                if (s == null) return;
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                if (Buffer == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Buffer);
                Buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return (Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(Buffer, Length / 2) : null) ??
                       throw new InvalidOperationException();
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SamRidEnumeration
        {
            public int Rid;
            public UnicodeString Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SrSecurityDescriptor
        {
            public int Length;
            public IntPtr SecurityDescriptor; // SecurityDescriptor**
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LogonHours
        {
            public ushort UnitsPerWeek;
            public IntPtr LogonHoursBitmap; // byte* (RTL bitmap, buffer)
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct UserAllInformation
        {
            public long LastLogon;
            public long LastLogoff;
            public long PasswordLastSet;
            public long AccountExpires;
            public long PasswordCanChange;
            public long PasswordMustChange;
            public UnicodeString UserName;
            public UnicodeString FullName;
            public UnicodeString HomeDirectory;
            public UnicodeString HomeDirectoryDrive;
            public UnicodeString ScriptPath;
            public UnicodeString ProfilePath;
            public UnicodeString AdminComment;
            public UnicodeString WorkStations;
            public UnicodeString UserComment;
            public UnicodeString Parameters;
            public UnicodeString LmPassword;
            public UnicodeString NtPassword;
            public UnicodeString publicData;
            public SrSecurityDescriptor SecurityDescriptor;
            public int UserId;
            public int PrimaryGroupId;
            public UserAccountFlags UserAccountControl;
            public UserWhichFields WhichFields;
            public LogonHours LogonHours;
            public ushort BadPasswordCount;
            public ushort LogonCount;
            public ushort CountryCode;
            public ushort CodePage;
            [MarshalAs(UnmanagedType.I1)]
            public bool LmPasswordPresent;
            [MarshalAs(UnmanagedType.I1)]
            public bool NtPasswordPresent;
            [MarshalAs(UnmanagedType.I1)]
            public bool PasswordExpired;
            [MarshalAs(UnmanagedType.I1)]
            public bool publicDataSensitive;
        }
    }
    public class SAMEnums
    {
        [Flags]
        public enum NtStatus
        {
            StatusSuccess = 0x0,
            StatusMoreEntries = 0x105,
            StatusSomeMapped = 0x107,
            StatusInvalidHandle = unchecked((int)0xC0000008),
            StatusInvalidParameter = unchecked((int)0xC000000D),
            StatusAccessDenied = unchecked((int)0xC0000022),
            StatusObjectTypeMismatch = unchecked((int)0xC0000024),
            StatusNoSuchDomain = unchecked((int)0xC00000DF),
            StatusRpcServerUnavailable = unchecked((int)0xC0020017),
            StatusNoSuchAlias = unchecked((int)0xC0000151),
            StatusNoMoreEntries = unchecked((int)0x8000001A),
            STATUS_USER_EXISTS = unchecked((int)0xC0000063L)
        }

        [Flags]
        public enum AliasOpenFlags
        {
            AddMember = 0x1,
            RemoveMember = 0x2,
            ListMembers = 0x4,
            ReadInfo = 0x8,
            WriteAccount = 0x10,
            AllAccess = 0xf001f,
            Read = 0x20004,
            Write = 0x20013,
            Execute = 0x20008
        }

        [Flags]
        public enum DomainAccessMask
        {
            ReadPasswordParameters = 0x1,
            WritePasswordParameters = 0x2,
            ReadOtherParameters = 0x4,
            WriteOtherParameters = 0x8,
            CreateUser = 0x10,
            CreateGroup = 0x20,
            CreateAlias = 0x40,
            GetAliasMembership = 0x80,
            ListAccounts = 0x100,
            Lookup = 0x200,
            AdministerServer = 0x400,
            AllAccess = 0xf07ff,
            Read = 0x20084,
            Write = 0x2047A,
            Execute = 0x20301
        }

        [Flags]
        public enum SamAccessMasks
        {
            SamServerConnect = 0x1,
            SamServerShutdown = 0x2,
            SamServerInitialize = 0x4,
            SamServerCreateDomains = 0x8,
            SamServerEnumerateDomains = 0x10,
            SamServerLookupDomain = 0x20,
            SamServerAllAccess = 0xf003f,
            SamServerRead = 0x20010,
            SamServerWrite = 0x2000e,
            SamServerExecute = 0x20021
        }

        [Flags]
        public enum UserAccountFlags : uint
        {
            Disabled = 0x1,
            HomeDirectoryRequired = 0x2,
            PasswordNotRequired = 0x4,
            TempDuplicateAccount = 0x8,
            NormalAccount = 0x10,
            MnsLogonAccount = 0x20,
            InterdomainTrustAccount = 0x40,
            WorkstationTrustAccount = 0x80,
            ServerTrustAccount = 0x100,
            DontExpirePassword = 0x200,
            AccountAutoLocked = 0x400,
            EncryptedTextPasswordAllowed = 0x800,
            SmartcardRequired = 0x1000,
            TrustedForDelegation = 0x2000,
            NotDelegated = 0x4000,
            UseDesKeyOnly = 0x8000,
            DontRequirePreauth = 0x10000,
            PasswordExpired = 0x20000,
            TrustedToAuthenticateForDelegation = 0x40000,
            NoAuthDataRequired = 0x80000,
            PartialSecretsAccount = 0x100000,
            UseAesKeys = 0x200000,
            CLEAR_UF_ACCOUNTDISABLE = 0xFFFFFFFE
        }

        [Flags]
        public enum SamUserAccess
        {
            ReadGeneral = 0x1,
            ReadPreferences = 0x2,
            WritePreferences = 0x4,
            ReadLogon = 0x8,
            ReadAccount = 0x10,
            WriteAccount = 0x20,
            ChangePassword = 0x40,
            ForcePasswordChange = 0x80,
            ListGroups = 0x100,
            ReadGroupInformation = 0x200,
            WriteGroupInformation = 0x400,
            UserAllAccess = 0xf07ff,
            Delete = 0x10000,
            WriteDac = 0x40000
        }

        [Flags]
        public enum UserWhichFields
        {
            Username = 0x1,
            Fullname = 0x2,
            UserId = 0x4,
            PrimaryGroupId = 0x8,
            AdminComment = 0x10,
            UserComment = 0x20,
            HomeDirectory = 0x40,
            HomeDirectoryDrive = 0x80,
            ScriptPath = 0x100,
            ProfilePath = 0x200,
            Workstations = 0x400,
            LastLogon = 0x800,
            LastLogoff = 0x1000,
            LogonHours = 0x2000,
            BadPasswordCount = 0x4000,
            LogonCount = 0x8000,
            PasswordCanChange = 0x10000,
            PasswordMustChange = 0x20000,
            PasswordLastSet = 0x40000,
            AccountExpires = 0x80000,
            UserAccountControl = 0x100000,
            Parameters = 0x200000,
            CountryCode = 0x400000,
            CodePage = 0x800000,
            NtPasswordPresent = 0x1000000,
            LmPasswordPresent = 0x2000000,
            publicData = 0x4000000,
            PasswordExpired = 0x8000000,
            SecurityDescriptor = 0x10000000,
            OwfPassword = 0x20000000,
            USER_ALL_USERACCOUNTCONTROL = 0x100000
        }

        public enum UserInformationClass : int
        {
            UserGeneralInformation = 1,
            UserPreferencesInformation,
            UserLogonInformation,
            UserLogonHoursInformation,
            UserAccountInformation,
            UserNameInformation,
            UserAccountNameInformation,
            UserFullNameInformation,
            UserPrimaryGroupInformation,
            UserHomeInformation,
            UserScriptInformation,
            UserProfileInformation,
            UserAdminCommentInformation,
            UserWorkStationsInformation,
            UserSetPasswordInformation,
            UserControlInformation,
            UserExpiresInformation,
            UserInternal1Information,
            UserInternal2Information,
            UserParametersInformation,
            UserAllInformation,
            UserInternal3Information,
            UserInternal4Information,
            UserInternal5Information,
            UserInternal4InformationNew,
            UserInternal5InformationNew,
            UserInternal6Information,
            UserExtendedInformation,
            UserLogonUIInformation
        }
    }

    [SuppressUnmanagedCodeSecurity]
    public static class SAMMethods
    {
        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamConnect(
            ref UnicodeString serverName,
            out IntPtr serverHandle,
            SamAccessMasks desiredAccess,
            bool trusted
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamEnumerateDomainsInSamServer(
            IntPtr serverHandle,
            ref int enumerationContext,
            out SamRidEnumeration[] buffer,
            int prefMaxLen,
            out int count
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamLookupDomainInSamServer(
            IntPtr serverHandle,
            ref UnicodeString name,
            out IntPtr sid
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamOpenDomain(
            IntPtr serverHandle,
            DomainAccessMask desiredAccess,
            IntPtr domainSid,
            out IntPtr domainHandle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamOpenAlias(
            IntPtr domainHandle,
            AliasOpenFlags desiredAccess,
            int aliasId,
            out IntPtr aliasHandle
        );

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamCloseHandle(
            IntPtr handle
        );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamCreateUser2InDomain(
            IntPtr DomainHandle,
            ref UnicodeString AccountName,
            UserAccountFlags AccountType,
            SamUserAccess DesiredAccess,
            out IntPtr UserHandle,
            out SamUserAccess GrantedAccess,
            out int RelativeId
            );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamSetInformationUser(
            IntPtr UserHandle,
            UserInformationClass UserInformationClass,
            IntPtr Buffer
            );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamLookupNamesInDomain(
            IntPtr DomainHandle,
            int Count,
            UnicodeString[] Names,
            out int[] RelativeIds,
            out IntPtr use
            );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus SamRidToSid(
            IntPtr DomainHandle,
            int RelativeId,
            out IntPtr Sid
            );

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        internal static extern NtStatus SamAddMemberToAlias(
            IntPtr AliasHandle,
            IntPtr MemberId
            );
    }
}