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
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;

using KeePass.Util;
using KeePass.Util.Spr;

using KeePassLib;
using KeePassLib.Delegates;
using KeePassLib.Interfaces;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace KeePassUtility
{
	public static class ReportingMod
	{
		//private const string CmdListGroups = "listgroups";
		//private const string CmdListEntries = "listentries";
		private const string CmdGetEntryString = "getentrystring";

		private const string ParamField = "Field";

		private const string ParamFailIfNotExists = "FailIfNotExists";
		private const string ParamFailIfNoEntry = "FailIfNoEntry";
		private const string ParamSprCompile = "Spr";

        
       
        public static bool GetEntryString(PwDatabase pwDb, string entry,out string password)
		{
            password = String.Empty;

            List<PwEntry> l = EntryMod.FindEntries(pwDb, entry);
			//if((args[ParamFailIfNoEntry] != null) && (l.Count == 0))
				//throw new Exception(KSRes.EntryNotFound);

			
			foreach(PwEntry pe in l)
			{

                //if(pe.Strings.Get(strField) == null)
                //throw new Exception(KSRes.FieldNotFound);


                password = pe.Strings.ReadSafe("Password");
                return true;
                /*
				if(bSprCompile)
				{
					SprContext ctx = new SprContext(pe, pwDb, SprCompileFlags.All,
						false, false);
					strData = SprEngine.Compile(strData, ctx);

					bNeedsSave = true;
				}
                */

            }

            return false;
		}
	}
}
