using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SAMRPCNative.SAMEnums;
using static SAMRPCNative.SAMStructs;
using static SAMRPCNative.SAMMethods;
using System.Runtime.Remoting.Channels;
using Microsoft.Win32;
using System.Security.Principal;

namespace SamrAddUser
{
    class Program
    {
        static void Main()
        {
            UnicodeString serverName = new UnicodeString("localhost");
            UnicodeString UserName = new UnicodeString("test");
            UnicodeString[] adminGroup = new UnicodeString[1];

            adminGroup[0] = new UnicodeString("administrators");

            IntPtr hServerHandle;
            IntPtr DomainHandle = IntPtr.Zero;
            IntPtr UserHandle = IntPtr.Zero;
            IntPtr hAdminGroup;

            IntPtr builtinDomainSid = IntPtr.Zero;
            IntPtr accountDomainSid = IntPtr.Zero;
            IntPtr userSID = IntPtr.Zero;

            IntPtr USE;

            NtStatus Status;
            NtStatus enumDomainStatus;

            int domainEnumerationContext = 0;
            int domainCountReturned = 0;
            int RelativeId = 0;
            int[] adminRID = new int[1];

            SamRidEnumeration[] pEnumDomainBuffer;           
            UserAllInformation uai = new UserAllInformation();

            SamUserAccess GrantedAccess;

            //10位随机密码
            string chars = "!@#$%0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            Random randrom = new Random((int)DateTime.Now.Ticks);
            string password = "";
            for (int i = 0; i < 10; i++)
            {
                password += chars[randrom.Next(chars.Length)];
            }

            Status = SamConnect(ref serverName, out hServerHandle, SamAccessMasks.SamServerConnect | SamAccessMasks.SamServerEnumerateDomains | SamAccessMasks.SamServerLookupDomain, false);
            if (Status == NtStatus.StatusSuccess) 
            {
                do
                {
                    enumDomainStatus = SamEnumerateDomainsInSamServer(hServerHandle, ref domainEnumerationContext, out pEnumDomainBuffer, 1, out domainCountReturned);
                    for (int i = 0; i < domainCountReturned; i++)
                    {
                        // Get Builtin Domain SID & Account Domain SID
                        if (pEnumDomainBuffer[i].Name.ToString() == "Builtin")
                            SamLookupDomainInSamServer(hServerHandle, ref pEnumDomainBuffer[i].Name, out builtinDomainSid);
                        else
                            SamLookupDomainInSamServer(hServerHandle, ref pEnumDomainBuffer[i].Name, out accountDomainSid);
                    }
                }
                while (enumDomainStatus == NtStatus.StatusMoreEntries);

                Status = SamOpenDomain(hServerHandle, DomainAccessMask.CreateUser | DomainAccessMask.Lookup | DomainAccessMask.ReadPasswordParameters, accountDomainSid, out DomainHandle);
                if (Status == NtStatus.StatusSuccess)
                {
                    Status = SamCreateUser2InDomain(DomainHandle, ref UserName, UserAccountFlags.NormalAccount, SamUserAccess.UserAllAccess | SamUserAccess.Delete | SamUserAccess.WriteDac, out UserHandle, out GrantedAccess, out RelativeId);
                    if (Status == NtStatus.StatusSuccess)
                    {
                        Console.WriteLine("[+] SamCreateUser2InDomain success.");
                        Console.WriteLine($"[*] User RID: {RelativeId}");
                        uai.NtPasswordPresent = true;
                        uai.WhichFields |= UserWhichFields.NtPasswordPresent;
                        // Clear the UF_ACCOUNTDISABLE to enable account
                        uai.UserAccountControl &= UserAccountFlags.CLEAR_UF_ACCOUNTDISABLE;
                        uai.UserAccountControl |= UserAccountFlags.NormalAccount;
                        uai.WhichFields |= UserWhichFields.USER_ALL_USERACCOUNTCONTROL;
                        uai.NtPassword = new UnicodeString(password);

                        unsafe
                        {
                            //Set password and userAccountControl
                            Status = SamSetInformationUser(UserHandle, UserInformationClass.UserAllInformation, new IntPtr(&uai));
                            if (Status == NtStatus.StatusSuccess)
                            {
                                Console.WriteLine($"[+] Add user {UserName} success.");
                                Console.WriteLine($"[+] Username: {UserName}\n[+] Password: {password}");
                            }
                            else
                            {
                                Console.WriteLine("[x] SamSetInformationUser error.");
                            }
                        }
                    }
                    else if (Status == NtStatus.STATUS_USER_EXISTS)
                    {
                        Console.WriteLine("[*] SamCreateUser2InDomain STATUS_USER_EXISTS");
                        return;
                    }
                    else
                    {
                        Console.WriteLine("[x] SamCreateUser2InDomain error.");
                    }
                }
                else
                {
                    Console.WriteLine("[x] SamOpenDomain error.");
                }

                Status = SamOpenDomain(hServerHandle, DomainAccessMask.Lookup, builtinDomainSid, out DomainHandle);
                if (Status == NtStatus.StatusSuccess)
                {
                    // Lookup Administrators in Builtin Domain                    
                    Status = SamLookupNamesInDomain(DomainHandle, 1, adminGroup, out adminRID, out USE);
                    if (Status == NtStatus.StatusSuccess)
                    {
                        Status = SamOpenAlias(DomainHandle, AliasOpenFlags.AddMember, adminRID[0], out hAdminGroup);
                        if (Status == NtStatus.StatusSuccess)
                        {
                            SamRidToSid(UserHandle, RelativeId, out userSID);
                            // Add user to Administrators
                            Status = SamAddMemberToAlias(hAdminGroup, userSID);
                            if (Status == NtStatus.StatusSuccess)
                            {
                                Console.WriteLine("[+] Add to Admin Group Successfully.");
                            }
                            else
                            {
                                Console.WriteLine("[x] AddMemberToAlias error.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("[x] SamOpenAlias error.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[x] SamLookupNamesInDomain error.");
                    }
                }
                else
                {
                    Console.WriteLine("[x] SamOpenDomain error.");
                }
            }
            else
            {
                Console.WriteLine("[x] Samconnect error.");
            }

            SamCloseHandle(UserHandle);
            SamCloseHandle(DomainHandle);
            SamCloseHandle(hServerHandle);
        }
    }
}
