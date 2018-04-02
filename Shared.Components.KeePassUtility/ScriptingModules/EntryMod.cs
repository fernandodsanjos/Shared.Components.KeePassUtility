/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2018 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;
using KeePass.Util;

using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Delegates;
using KeePassLib.Native;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KeePassUtility
{
	public static class EntryMod
	{
		private const string CmdAddEntry = "addentry";
		private const string CmdAddEntries = "addentries";
		private const string CmdEditEntry = "editentry";
		private const string CmdMoveEntry = "moveentry";
		private const string CmdDeleteEntry = "deleteentry";
		private const string CmdDeleteAllEntries = "deleteallentries";

		internal const string ParamGroupName = "GroupName";
		internal const string ParamGroupPath = "GroupPath";
		private const string ParamGroupTree = "GroupTree"; // Obsolete

		private const string ParamIcon = "setx-Icon";
		private const string ParamCustomIcon = "setx-CustomIcon";
		private const string ParamSetExpires = "setx-Expires";
		private const string ParamSetExpiryTime = "setx-ExpiryTime";

		private const string ParamUserNameList = "UserList";
		private const string ParamPasswordList = "PasswordList";
		private const string ParamTitleList = "TitleList";
		private const string ParamNotesList = "NotesList";
		private const string ParamUrlList = "UrlList";

		private const string ParamDeleteAllExisting = "DeleteExisting";

		private const string ParamCreateBackup = "CreateBackup";

		private static bool EntryMatches(PwEntry pe, string entry)
		{
			
				bool bFound = false;
				foreach(KeyValuePair<string, ProtectedString> kvpStr in pe.Strings)
				{

              
                    if (string.Equals(kvpStr.Key, "Title", StrUtil.CaseIgnoreCmp))
					{
						string strData = kvpStr.Value.ReadString();

                        bFound = (entry == strData);

						
					}
				}
				

			return bFound;
		}

		internal static List<PwEntry> FindEntries(PwDatabase pwDb, string entry)
		{
			List<PwEntry> l = new List<PwEntry>();

			EntryHandler eh = delegate(PwEntry pe)
			{
				if(EntryMatches(pe, entry)) l.Add(pe);
				return true;
			};

			pwDb.RootGroup.TraverseTree(TraversalMethod.PreOrder, null, eh);
			return l;
		}

        public static void GetAllEntries(PwDatabase pwDb, out ConcurrentDictionary<string, KeyValuePair<string, string>> dictionary)
        {
            PwObjectList<PwEntry> entries = pwDb.RootGroup.GetEntries(true);
            dictionary = new ConcurrentDictionary<string, KeyValuePair<string, string>>();

            foreach (PwEntry entry in entries)
            {
                string username = string.Empty;
                string password = string.Empty;
                string title = string.Empty;

                foreach (KeyValuePair<string, ProtectedString> kvp in entry.Strings)
                {
                   if(kvp.Key == "UserName")
                        username = kvp.Value.ReadString();

                   if (kvp.Key == "Password")
                        password = kvp.Value.ReadString();

                    if (kvp.Key == "Title")
                        title = kvp.Value.ReadString();
                }

                if(String.IsNullOrEmpty(username) == false && String.IsNullOrEmpty(password) == false)
                    dictionary.TryAdd(title, new KeyValuePair<string, string>(username, password));

            }
        
           

           
            
        }


    }
}
