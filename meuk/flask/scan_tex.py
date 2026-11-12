#!/usr/bin/env python3
"""Genereer een LaTeX-notitie uit een scan-run van scan-domein (apm2).

Leest een run-map (raw/<run>/) en bouwt een rauw-LaTeX fragment met twee
secties: (1) stappen en status, (2) DigiD-normkoppeling + bevindingen-
samenvatting. Bedoeld als rauwe-LaTeX notitie in het IB-rapport.

Standalone:  python3 -m meuk.flask.scan_tex <run_dir> [-o uit.tex] [--taal nl|en]
"""
import csv
import json
import os
import re

# DigiD-normcodes (hoofdcodes) die in de ingebouwde digid-checklist voorkomen.
_CHECKLISTS_JSON = os.path.join(os.path.dirname(__file__), 'db', 'checklists.json')


def _tex(text):
    """Escape dynamische tekst voor LaTeX (het omliggende fragment is rauw)."""
    if text is None:
        return ''
    s = str(text)
    for old, new in [('\\', r'\textbackslash{}'), ('&', r'\&'), ('%', r'\%'),
                     ('$', r'\$'), ('#', r'\#'), ('_', r'\_'), ('{', r'\{'),
                     ('}', r'\}'), ('~', r'\textasciitilde{}'),
                     ('^', r'\textasciicircum{}')]:
        s = s.replace(old, new)
    return s


def _read_json(path, default=None):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def digid_norm_codes():
    """Hoofd-normcodes uit de digid-checklist (bijv. U/WA.03, U/PW.03)."""
    data = _read_json(_CHECKLISTS_JSON, {}) or {}
    codes = []
    digid = (data.get('checklists', {}) or {}).get('digid', {})
    for phase in digid.get('phases', []):
        if phase.get('id') != 'digid_norm':
            continue
        for it in phase.get('items', []):
            title = it.get('title', '')
            code = title.split(' — ', 1)[0].strip() if ' — ' in title else title.strip()
            if code:
                codes.append(code)
    return codes


def _read_text(path, limit=None):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            data = f.read()
    except OSError:
        return ''
    return data[:limit] if limit else data


# Logische volgorde van scanstappen (recon -> resolutie -> web -> scans).
_STEP_ORDER = ['traceroute', 'host', 'nslookup', 'dns_', 'http_', 'certificate',
               'nmap', 'nikto', 'nuclei', 'testssl', 'sqlmap', 'browser']


def _step_rank(step):
    for i, pre in enumerate(_STEP_ORDER):
        if step == pre or step.startswith(pre):
            return i
    return len(_STEP_ORDER)


def _shorten_paths(text, run_name='', generic=True):
    """Kort lange paden in voor leesbaarheid: paden met de run-naam en (optioneel)
    overige lange absolute paden worden …/<bestandsnaam>."""
    if not text:
        return text
    if run_name:
        text = re.sub(r'\S*/' + re.escape(run_name) + r'\S*',
                      lambda m: '…/' + m.group(0).rsplit('/', 1)[-1], text)
    if generic:
        home_like = ('/Users/', '/home/', '/root/', '/opt/', '/private/',
                     '/tmp/', '/var/')

        def _short(m):
            tok = m.group(0)
            segs = [s for s in tok.split('/') if s]
            if tok.startswith(home_like) or len(tok) > 40 or tok.count('/') >= 3:
                return ('…/' + segs[-1]) if segs else '…'
            return tok
        text = re.sub(r'/\S+', _short, text)
    return text


def _tex_breakable(text):
    """Escape voor LaTeX én voeg breekpunten toe na scheidingstekens, zodat
    lange commando's in \\opdracht{} en de lstlisting-caption afbreken i.p.v.
    uit de marge lopen."""
    s = _tex(text)
    # \allowbreak = neutrale breekkans; breekt alleen als de regel te lang is.
    for sep in ('/', r'\_', '-', '=', ':', r'\&', '?', ';', ','):
        s = s.replace(sep, sep + r'\allowbreak{}')
    return s


def _cmd_caption(command, run_name=''):
    """Eén-regelig, begrensd commando (gedeeld door caption en intro-zin).
    Lange paden worden ingekort; lange curl/python-commando's breken anders."""
    cap = _shorten_paths(command or '(leeg)', run_name, generic=True)
    cap = ' '.join(cap.split())
    if len(cap) > 200:
        cap = cap[:200] + ' …'
    return cap


def _lstlisting(response, command_cap, run_name='', max_lines=60, max_chars=4000):
    """lstlisting-blok met het (reeds begrensde) commando als caption en de
    response als inhoud."""
    caption = _tex_breakable(command_cap or '(leeg)')
    text = _shorten_paths(response or '(geen output)', run_name, generic=False)
    # Verwijder control-chars behalve newline/tab
    text = ''.join(ch for ch in text if ch in '\n\t' or ord(ch) >= 32)
    # lstlisting-inhoud mag de eind-marker niet bevatten
    text = text.replace(r'\end{lstlisting}', r'\ end{lstlisting}')
    lines = text.splitlines()
    truncated = False
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated = True
    text = '\n'.join(lines)
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True
    text = text.rstrip()
    if truncated:
        text += '\n... (afgekapt; volledige output in de scan-run-map)'
    return (r'\begin{lstlisting}[caption={%s}]' % caption) + '\n' + text + '\n' + r'\end{lstlisting}'


def _step_command_response(run_dir, step):
    """Lees (command, response, status, exitcode) voor een stap-map."""
    sd = os.path.join(run_dir, 'steps', step)
    res = _read_json(os.path.join(sd, 'result.json'), {}) or {}
    attempt = res.get('attempt')
    adir = os.path.join(run_dir, attempt) if attempt else None
    if not adir or not os.path.isdir(adir):
        # val terug op de enige attempt-* submap
        subs = [d for d in os.listdir(sd) if d.startswith('attempt-')] if os.path.isdir(sd) else []
        adir = os.path.join(sd, subs[0]) if subs else sd
    command = _read_text(os.path.join(adir, 'command.txt')).strip()
    response = ''
    for fn in ('stdout.txt', 'headers.txt', 'stderr.txt'):
        response = _read_text(os.path.join(adir, fn)).strip()
        if response:
            break
    return command, response, res.get('status', ''), res.get('exitcode', '')


def _read_csv(path):
    rows = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            rows = list(csv.DictReader(f))
    except OSError:
        pass
    return rows


def _read_status(run_dir):
    rows = []
    path = os.path.join(run_dir, 'status.tsv')
    try:
        with open(path, encoding='utf-8') as f:
            for r in csv.DictReader(f, delimiter='\t'):
                rows.append(r)
    except OSError:
        pass
    return rows


def build_scan_tex(run_dir, taal='nl', include_steps=True):
    """Bouw (naam, latex_fragment) voor een scan-run-map."""
    _en = taal == 'en'
    run_dir_abs = os.path.abspath(run_dir)
    run_name = os.path.basename(os.path.normpath(run_dir_abs))
    cfg = _read_json(os.path.join(run_dir, 'config.json'), {}) or {}
    cov = _read_json(os.path.join(run_dir, 'ncsc-coverage.json'), {}) or {}
    overview = _read_json(os.path.join(run_dir, 'findings-overview.json'), {}) or {}
    status_rows = _read_status(run_dir)

    domein = cfg.get('domain') or os.path.basename(run_dir.rstrip('/'))

    def L(nl, en):
        return en if _en else nl

    naam = 'Scan: {}'.format(domein)

    # Geen eigen titel: de notitienaam levert al de \subsection-kop in het rapport
    # (anders een dubbel "Scan: <domein>"-kopje).
    out = []

    # ── Metadata ─────────────────────────────────────────────────────────
    scope = cfg.get('scope', {}) or {}
    scope_str = '; '.join('{} ({})'.format(h, ', '.join(ips))
                          for h, ips in scope.items()) if isinstance(scope, dict) else ''
    meta = [
        (L('Doel', 'Target'), domein),
        ('URL', cfg.get('url', '')),
        (L('Profiel', 'Profile'), cfg.get('profile', '')),
        (L('Sessie', 'Session'), cfg.get('session', '')),
        (L('Datum', 'Date'), cfg.get('created', '')),
        (L('Scriptversie', 'Script version'), cfg.get('script_version', '')),
        (L('Scope', 'Scope'), scope_str),
        (L('Poorten', 'Ports'), ', '.join(str(p) for p in (cfg.get('ports') or []))),
    ]
    out.append(r'\begin{itemize}')
    for lbl, val in meta:
        if val:
            out.append(r'  \item \textbf{%s:} %s' % (_tex(lbl), _tex(val)))
    out.append(r'\end{itemize}')

    # ── Sectie 1: stappen en status ──────────────────────────────────────
    out.append(r'\subsubsection*{%s}' % _tex(L('Stappen en status', 'Steps and status')))
    counts = {}
    endpoints_done = 0
    notable = []
    for r in status_rows:
        st = r.get('status', '')
        counts[st] = counts.get(st, 0) + 1
        stap = r.get('stap', '')
        if stap.startswith('endpoint_'):
            if st == 'afgerond':
                endpoints_done += 1
            else:
                notable.append(r)
        elif st != 'afgerond':
            notable.append(r)
    samenvatting = ', '.join('{} {}'.format(v, _tex(k)) for k, v in sorted(counts.items()))
    out.append(r'\noindent %s \textbf{%d} %s (%s).' % (
        _tex(L('In totaal', 'In total')), len(status_rows),
        _tex(L('stappen', 'steps')), samenvatting))
    if endpoints_done:
        out.append(r'\par\noindent %s \textbf{%d} %s.' % (
            _tex(L('Waarvan', 'Of which')), endpoints_done,
            _tex(L('endpoint-stappen afgerond', 'endpoint steps completed'))))
    if notable:
        out.append(r'\par\vspace{3pt}\noindent\textit{%s}' % _tex(
            L('Stappen die niet volledig zijn afgerond:', 'Steps not fully completed:')))
        out.append(r'\begin{longtable}{>{\raggedright\arraybackslash}p{3.2cm} '
                   r'>{\raggedright\arraybackslash}p{2.4cm} '
                   r'>{\raggedright\arraybackslash}p{1.6cm} '
                   r'>{\raggedright\arraybackslash}p{6.0cm}}')
        out.append(r'\rowcolor{rijkblauw}\textcolor{white}{\textbf{%s}} & \textcolor{white}{\textbf{%s}} & \textcolor{white}{\textbf{%s}} & \textcolor{white}{\textbf{%s}} \\ \hline \endhead' % (
            _tex(L('Stap', 'Step')), _tex('Status'),
            _tex(L('Exitcode', 'Exit code')), _tex(L('Reden', 'Reason'))))
        for r in notable:
            out.append(r'%s & %s & %s & %s \\' % (
                _tex(r.get('stap', '')), _tex(r.get('status', '')),
                _tex(r.get('exitcode', '')), _tex(r.get('reden', ''))))
        out.append(r'\end{longtable}')

    # ── Sectie 2: DigiD-normkoppeling ────────────────────────────────────
    out.append(r'\subsubsection*{%s}' % _tex(L('DigiD-normkoppeling', 'DigiD norm mapping')))
    out.append(r'\noindent\textit{%s}' % _tex(L(
        'Geen complianceverklaring: elke normbeoordeling blijft "niet vastgesteld". '
        'Een kandidaat-koppeling is geen bewezen normafwijking.',
        'No compliance statement: every norm assessment remains "not determined". '
        'A candidate mapping is not a proven non-compliance.')))

    controls = {c.get('id'): c for c in cov.get('controls', []) if isinstance(c, dict)}
    dcodes = digid_norm_codes()
    covered = []
    for code in dcodes:
        main = controls.get(code)
        subs = [c for cid, c in controls.items()
                if cid != code and cid.startswith(code + '/') and c.get('finding_ids')]
        n_main = len(main.get('finding_ids', [])) if main else 0
        if n_main or subs:
            covered.append((code, main, subs, n_main))
    if covered:
        out.append(r'\par\vspace{3pt}')
        out.append(r'\begin{itemize}')
        for code, main, subs, n_main in covered:
            title = (main or {}).get('title', '')
            assess = (main or {}).get('norm_assessment', 'niet vastgesteld')
            out.append(r'  \item \textbf{%s%s} --- %d %s (%s: %s)' % (
                _tex(code), _tex(' — ' + title if title else ''), n_main,
                _tex(L('gekoppelde bevinding(en)', 'linked finding(s)')),
                _tex(L('normoordeel', 'assessment')), _tex(assess)))
            if subs:
                out.append(r'  \begin{itemize}')
                for sc in subs:
                    out.append(r'    \item %s%s: %d' % (
                        _tex(sc.get('id', '')),
                        _tex(' — ' + sc.get('title', '') if sc.get('title') else ''),
                        len(sc.get('finding_ids', []))))
                out.append(r'  \end{itemize}')
        out.append(r'\end{itemize}')
        niet = [c for c in dcodes if c not in [cc[0] for cc in covered]]
        if niet:
            out.append(r'\par\noindent %s %s.' % (
                _tex(L('Niet door deze scan geraakt:', 'Not touched by this scan:')),
                _tex(', '.join(niet))))
    else:
        out.append(r'\par\noindent %s' % _tex(L(
            'Geen van de DigiD-normen is in deze scan aan een bevinding gekoppeld.',
            'None of the DigiD norms were linked to a finding in this scan.')))

    # ── Sectie 3: bevindingen-samenvatting ───────────────────────────────
    out.append(r'\subsubsection*{%s}' % _tex(L('Bevindingen-samenvatting', 'Findings summary')))
    ts = overview.get('testssl_severity_counts', {}) or {}
    if ts:
        out.append(r'\par\noindent\textbf{testssl:} %s' % _tex(
            ', '.join('{}: {}'.format(k, v) for k, v in ts.items())))
    nuclei = overview.get('nuclei', []) or []
    out.append(r'\par\noindent\textbf{nuclei:} %d %s' % (
        len(nuclei), _tex(L('bevinding(en)', 'finding(s)'))))
    ports = overview.get('nmap_open_ports', []) or []
    if ports:
        out.append(r'\par\vspace{3pt}\noindent\textbf{%s}' % _tex(L('Open poorten (nmap):', 'Open ports (nmap):')))
        out.append(r'\begin{longtable}{>{\raggedright\arraybackslash}p{3.4cm} '
                   r'>{\raggedright\arraybackslash}p{1.6cm} '
                   r'>{\raggedright\arraybackslash}p{8.0cm}}')
        out.append(r'\rowcolor{rijkblauw}\textcolor{white}{\textbf{IP}} & \textcolor{white}{\textbf{%s}} & \textcolor{white}{\textbf{%s}} \\ \hline \endhead' % (
            _tex(L('Poort', 'Port')), _tex(L('Service', 'Service'))))
        for p in ports:
            svc = p.get('service', {}) or {}
            svc_str = ' '.join(x for x in [svc.get('name', ''), svc.get('product', ''),
                                           svc.get('version', '')] if x)
            out.append(r'%s & %s/%s & %s \\' % (
                _tex(p.get('ip', '')), _tex(p.get('port', '')),
                _tex(p.get('protocol', '')), _tex(svc_str)))
        out.append(r'\end{longtable}')

    # ── Sectie 3b: cookies en security-headers ───────────────────────────
    cookies = _read_csv(os.path.join(run_dir, 'cookies-analysis.csv')) or \
        _read_csv(os.path.join(run_dir, 'cookie-analysis.csv'))
    header_obs = _read_json(os.path.join(run_dir, 'header-observations.json'), []) or []
    if cookies or header_obs:
        out.append(r'\subsubsection*{%s}' % _tex(L('Cookies en security-headers', 'Cookies and security headers')))
    if cookies:
        # Dedupliceer op cookie-configuratie (naam + attributen)
        seen = {}
        for c in cookies:
            key = (c.get('name', ''), c.get('secure', ''), c.get('httponly', ''),
                   c.get('samesite', ''), c.get('domain', ''), c.get('path', ''))
            seen.setdefault(key, c)
        out.append(r'\par\vspace{3pt}\noindent\textbf{%s}' % _tex(L('Cookies:', 'Cookies:')))
        out.append(r'\begingroup\footnotesize')
        out.append(r'\begin{longtable}{>{\raggedright\arraybackslash}p{2.6cm} '
                   r'>{\raggedright\arraybackslash}p{1.3cm} '
                   r'>{\raggedright\arraybackslash}p{1.3cm} '
                   r'>{\raggedright\arraybackslash}p{1.6cm} '
                   r'>{\raggedright\arraybackslash}p{6.0cm}}')
        out.append(r'\rowcolor{rijkblauw}\textcolor{white}{\textbf{%s}} & \textcolor{white}{\textbf{Secure}} & \textcolor{white}{\textbf{HttpOnly}} & \textcolor{white}{\textbf{SameSite}} & \textcolor{white}{\textbf{%s}} \\ \hline \endhead' % (
            _tex(L('Naam', 'Name')), _tex(L('Beoordeling', 'Assessment'))))
        for c in seen.values():
            review = c.get('review', '') or '—'
            out.append(r'%s & %s & %s & %s & %s \\' % (
                _tex(c.get('name', '')), _tex(c.get('secure', '')),
                _tex(c.get('httponly', '')), _tex(c.get('samesite', '')),
                _tex(review)))
        out.append(r'\end{longtable}\endgroup')
    if header_obs:
        # Dedupliceer op observatie-tekst
        obs = []
        seen_obs = set()
        for h in header_obs:
            o = (h.get('observation') or '').strip()
            if o and o not in seen_obs:
                seen_obs.add(o)
                obs.append(o)
        if obs:
            out.append(r'\par\vspace{3pt}\noindent\textbf{%s}' % _tex(L('Security-headers (observaties):', 'Security headers (observations):')))
            out.append(r'\begin{itemize}')
            for o in obs:
                out.append(r'  \item %s' % _tex(o))
            out.append(r'\end{itemize}')
            out.append(r'\par\noindent\textit{%s}' % _tex(L(
                'Een ontbrekende header is niet automatisch een kwetsbaarheid; context bepaalt de beoordeling.',
                'A missing header is not automatically a vulnerability; context determines the assessment.')))

    # ── Sectie 4: commando's en responses per stap ───────────────────────
    if include_steps:
        steps_root = os.path.join(run_dir, 'steps')
        step_names = []
        if os.path.isdir(steps_root):
            for s in sorted(os.listdir(steps_root)):
                if s.startswith('endpoint_') or s.startswith('version_'):
                    continue
                if os.path.isdir(os.path.join(steps_root, s)):
                    step_names.append(s)
        if step_names:
            step_names.sort(key=lambda s: (_step_rank(s), s))
            out.append(r'\subsubsection*{%s}' % _tex(
                L("Commando's en responses per stap", 'Commands and responses per step')))
            out.append(r'\par\noindent %s' % _tex(L(
                'Per stap: het uitgevoerde commando (bijschrift) met de response eronder.',
                'Per step: the executed command (caption) with its response below.')))
            for step in step_names:
                cmd, resp, _st, _code = _step_command_response(run_dir, step)
                if not cmd and not resp:
                    continue
                cmd_cap = _cmd_caption(cmd, run_name=run_name)
                out.append(r'\subsubsection{%s}' % _tex(step))
                out.append(r'\par\noindent %s \opdracht{%s} %s' % (
                    _tex(L('De volgende opdracht', 'The following command')),
                    _tex_breakable(cmd_cap),
                    _tex(L('gaf de volgende response:', 'gave the following response:'))))
                out.append(_lstlisting(resp, cmd_cap, run_name=run_name))

    out.append(r'\par\vspace{3pt}\noindent\textit{%s}' % _tex(L(
        'Volledige evidence in de scan-run-map; dit is een samenvatting.',
        'Full evidence in the scan run directory; this is a summary.')))

    return naam, '\n'.join(out)


def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description='Genereer LaTeX-notitie uit een scan-run.')
    ap.add_argument('run_dir', help='Pad naar de scan-run-map (raw/<run>/)')
    ap.add_argument('-o', '--output', help='Schrijf naar dit .tex-bestand (standaard: stdout)')
    ap.add_argument('--taal', default='nl', choices=['nl', 'en'])
    ap.add_argument('--no-steps', action='store_true',
                    help='laat de commando/response-sectie weg')
    args = ap.parse_args(argv)
    if not os.path.isdir(args.run_dir):
        raise SystemExit('Map niet gevonden: {}'.format(args.run_dir))
    naam, tex = build_scan_tex(args.run_dir, taal=args.taal, include_steps=not args.no_steps)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(tex + '\n')
        print('Geschreven: {} ({})'.format(args.output, naam))
    else:
        print(tex)


if __name__ == '__main__':
    _main()
