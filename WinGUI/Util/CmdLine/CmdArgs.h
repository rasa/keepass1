/*==========================================================================
Copyright (c) 2006, Bill Rubin <rubin@contractor.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright 
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.

    * Neither the name of Quality Object Software, Inc., nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.
==========================================================================*/

// DR 2008-09-10: Added 'lock' command line option

#pragma once
#include "FullPathName.h"

/*
The CmdArgs class parses the command line into the database path/name 
and the various options.  Along the way, it invokes GetFullPathName() 
to convert all paths to canonical form.

The CmdArgs class provides comprehensive command line error reporting,
invoking a MessageBox for every command line argument that is not used, 
giving the reason for not using it.

CmdArgs uses the singleton design pattern.
CmdArgs objects are immutable.
*/

class CmdArgs {
public:
    static CPP_FN_SHARE const CmdArgs& instance();

    const FullPathName& getDatabase() const {return m_database;}
    const FullPathName&  getKeyfile() const {return m_keyfile;}
    bool        preselectIsInEffect() const {return m_isPreselect;}
    bool         readonlyIsInEffect() const {return m_isReadOnly;}
    const std_string&   getPassword() const {return m_Password;}
	bool             lockIsInEffect() const {return m_isLock;}

private:
    CmdArgs();

    FullPathName m_database;
    FullPathName m_keyfile;
    bool         m_isPreselect;
    bool         m_isReadOnly;
    std_string   m_Password;  // empty() <==> not set
    bool         m_isLock;
};