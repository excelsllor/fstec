import { useEffect, useState, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  Alert,
  IconButton,
  Grid,
  Card,
  CardContent,
  Snackbar,
  FormControl,
  Select,
  MenuItem,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  TextField,
  Divider,
} from "@mui/material";
import {
  ArrowBack as BackIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
} from "@mui/icons-material";
import {
  lettersApi,
  type LetterResponse,
  type IoCResponse,
} from "../api/client";

const iocTypeLabels: Record<string, string> = {
  ip: "IP-адрес",
  domain: "Домен",
  hash: "Хэш",
  email: "Email",
  bdu: "BDU",
  cve: "CVE",
};

const iocChipColors: Record<string, "primary" | "secondary" | "info" | "success" | "warning" | "error" | "default"> = {
  ip: "info",
  domain: "success",
  hash: "warning",
  email: "secondary",
  bdu: "primary",
  cve: "default",
};

const severityLabels: Record<string, string> = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  unknown: "Неизвестно",
};

const threatTypeLabels: Record<string, string> = {
  phishing: "Фишинг",
  malware_attack: "Целевая атака",
  vulnerability: "Уязвимость",
  compromise: "Компрометация",
  clickfix: "ClickFix",
};

const severityColors: Record<string, "error" | "warning" | "info" | "success" | "default"> = {
  critical: "error",
  high: "warning",
  medium: "info",
  low: "success",
  unknown: "default",
};

const actionTypeOptions = [
  {
    value: "",
    label: "Авто (по умолчанию)",
    desc: "Включить стандартной фразой: обновление ПО либо переход на отечественные ОС (для Windows).",
  },
  {
    value: "update",
    label: "Обновление",
    desc: "Форсировать фразу об обновлении программного обеспечения до неуязвимой версии.",
  },
  {
    value: "skip",
    label: "Не включать",
    desc: "Не вставлять в текст; при совпадении ПО с описанием добавится нота «... не используется».",
  },
  {
    value: "exclude",
    label: "Исключить",
    desc: "Полностью исключить уязвимость из ответа (BDU не упоминается).",
  },
];

export default function LetterDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [letter, setLetter] = useState<LetterResponse | null>(null);
  const [tab, setTab] = useState(0);
  const [loading, setLoading] = useState(true);
  const [snack, setSnack] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await lettersApi.get(Number(id));
      setLetter(data);
    } catch (err) {
      console.error(err?.message || "Error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [id]);

  const handleGenerate = async () => {
    try {
      await lettersApi.generate(Number(id));
      setSnack("Ответ сгенерирован");
    } catch (err: any) {
      setSnack("Ошибка: " + (err.response?.data?.detail || "неизвестная"));
    }
  };

  const handleExport = async (type: string) => {
    try {
      const { data } = await lettersApi.exportIocs(Number(id), type);
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      const filenames: Record<string, string> = {
        emails: "emails.txt",
        ip_addresses: "ip_addresses.txt",
        domains: "domains.txt",
        ioc_indicators: "ioc_indicators.txt",
      };
      a.download = filenames[type] || `${type}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setSnack("Ошибка экспорта");
    }
  };

  const handleExportDocx = async (type: string) => {
    try {
      const { data } = await lettersApi.exportIocsDocx(Number(id), type);
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      const filenames: Record<string, string> = {
        emails: "emails.docx",
        ip_addresses: "ip-адреса на блокировку.docx",
        domains: "Адреса на блокировку.docx",
        ioc_indicators: "ioc_indicators.docx",
      };
      a.download = filenames[type] || `${type}.docx`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setSnack("Ошибка экспорта");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSnack("Скопировано");
  };

  if (loading) return <Typography>Загрузка...</Typography>;
  if (!letter) return <Alert severity="error">Письмо не найдено</Alert>;

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", mb: 2, gap: 1 }}>
        <IconButton onClick={() => navigate("/letters")}>
          <BackIcon />
        </IconButton>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>
          Письмо № {letter.letter_number || letter.id}
        </Typography>
      </Box>

      {letter.parse_errors && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Ошибки парсинга: {letter.parse_errors}
        </Alert>
      )}

      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Информация" />
        <Tab label={`Угрозы (${letter.threats.length})`} />
        <Tab label={`IOC (${letter.iocs.length})`} />
        <Tab label={`Уязвимости (${letter.vulnerabilities.length})`} />
        <Tab label="Ответ" />
        <Tab label="Экспорт" />
      </Tabs>

      {tab === 0 && <InfoTab letter={letter} />}
      {tab === 1 && <ThreatsTab letter={letter} />}
      {tab === 2 && <IocTab iocs={letter.iocs} onCopy={copyToClipboard} />}
      {tab === 3 && <VulnTab letter={letter} onSaved={load} />}
      {tab === 4 && <ResponseTab letter={letter} onGenerate={handleGenerate} />}
      {tab === 5 && <ExportTab onExport={handleExport} onExportDocx={handleExportDocx} counts={letter.iocs} />}

      <Snackbar
        open={!!snack}
        autoHideDuration={3000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
}

function InfoTab({ letter }: { letter: LetterResponse }) {
  return (
    <Grid container spacing={2}>
      <Grid size={{ xs: 12, md: 6 }}>
        <Paper sx={{ p: 2 }}>
          <Typography variant="subtitle1" gutterBottom>Основная информация</Typography>
          <Table size="small">
            <TableBody>
              <TableRow><TableCell>Номер</TableCell><TableCell>{letter.letter_number || "—"}</TableCell></TableRow>
              <TableRow><TableCell>Дата</TableCell><TableCell>{letter.letter_date || "—"}</TableCell></TableRow>
              <TableRow><TableCell>Тип</TableCell><TableCell>{letter.letter_type}</TableCell></TableRow>
              <TableRow><TableCell>Статус</TableCell><TableCell>{letter.status}</TableCell></TableRow>
              <TableRow><TableCell>Создано</TableCell><TableCell>{new Date(letter.created_at).toLocaleString("ru-RU")}</TableCell></TableRow>
            </TableBody>
          </Table>
        </Paper>
      </Grid>
      <Grid size={{ xs: 12, md: 6 }}>
        <Paper sx={{ p: 2 }}>
          <Typography variant="subtitle1" gutterBottom>Вложения ({letter.attachments.length})</Typography>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Файл</TableCell>
                <TableCell>Тип</TableCell>
                <TableCell>Статус</TableCell>
                <TableCell align="right">Символов</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {letter.attachments.map((a) => (
                <TableRow key={a.id}>
                  <TableCell>{a.filename}</TableCell>
                  <TableCell>{a.file_type}</TableCell>
                  <TableCell>
                    <Chip
                      label={a.parse_status === "ok" ? "OK" : a.parse_status}
                      color={a.parse_status === "ok" ? "success" : "warning"}
                      size="small"
                    />
                  </TableCell>
                  <TableCell align="right">{a.parsed_text.length}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      </Grid>
      {letter.parse_errors && (
        <Grid size={{ xs: 12 }}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="subtitle1" color="error" gutterBottom>Ошибки парсинга</Typography>
            <Typography variant="body2" component="pre" sx={{ whiteSpace: "pre-wrap" }}>
              {letter.parse_errors}
            </Typography>
          </Paper>
        </Grid>
      )}
    </Grid>
  );
}

function ThreatsTab({ letter }: { letter: LetterResponse }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  if (letter.threats.length === 0) {
    return <Alert severity="info">Угрозы не обнаружены</Alert>;
  }
  return (
    <Box>
      {letter.threats.map((t) => {
        const isExpanded = expanded === t.id;
        const threatText = threatOnlyText(t.description);
        const isLong = threatText.length > 500;
        return (
        <Card key={t.id} sx={{ mb: 2 }}>
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, flexWrap: "wrap" }}>
              <Chip label={`#${t.number}`} color="primary" size="small" />
              {t.group_name && <Chip label={t.group_name} color="error" size="small" />}
              {t.threat_type && <Chip label={threatTypeLabels[t.threat_type] || t.threat_type} size="small" variant="outlined" />}
              {t.malware_type && <Chip label={t.malware_type} color="warning" size="small" />}
              {t.theme && <Chip label={t.theme} size="small" variant="outlined" />}
            </Box>
            <Typography variant="body2" sx={{ mb: 1, whiteSpace: "pre-wrap" }}>
              {isExpanded ? threatText : threatText.slice(0, 500)}
              {isLong && !isExpanded && "..."}
            </Typography>
            {isLong && (
              <Button size="small" onClick={() => setExpanded(isExpanded ? null : t.id)} sx={{ mb: 1 }}>
                {isExpanded ? "Свернуть" : "Показать полностью"}
              </Button>
            )}
            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
              {t.archive_name && (
                <Typography variant="caption" color="text.secondary">
                  Архив: {t.archive_name}
                </Typography>
              )}
              {t.exe_name && (
                <Typography variant="caption" color="text.secondary">
                  Файл: {t.exe_name}
                </Typography>
              )}
            </Box>
          </CardContent>
        </Card>
        );
      })}
    </Box>
  );
}

function IocTab({ iocs, onCopy }: { iocs: IoCResponse[]; onCopy: (text: string) => void }) {
  const types = ["ip", "domain", "hash", "email", "bdu", "cve"];
  return (
    <Box>
      {types.map((type) => {
        const filtered = iocs.filter((i) => i.ioc_type === type);
        if (filtered.length === 0) return null;
        return (
          <Paper key={type} sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
              <Typography variant="subtitle1">
                {iocTypeLabels[type] || type} ({filtered.length})
              </Typography>
              <Button
                size="small"
                startIcon={<CopyIcon />}
                onClick={() => onCopy(filtered.map((i) => i.value).join("\n"))}
              >
                Копировать
              </Button>
            </Box>
            <TableContainer>
              <Table size="small">
                <TableBody>
                  {filtered.map((ioc) => (
                    <TableRow key={ioc.id} hover>
                      <TableCell sx={{ fontFamily: "monospace" }}>{ioc.value}</TableCell>
                      <TableCell align="right">
                        <IconButton size="small" onClick={() => onCopy(ioc.value)}>
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        );
      })}
      {iocs.length === 0 && <Alert severity="info">IOC не обнаружены</Alert>}
    </Box>
  );
}

function VulnTab({ letter, onSaved }: { letter: LetterResponse; onSaved?: () => void }) {
  const [drafts, setDrafts] = useState<Record<number, { action_type: string; software: string }>>({});
  const [savingId, setSavingId] = useState<number | null>(null);
  const [snack, setSnack] = useState("");

  useEffect(() => {
    const initial: Record<number, { action_type: string; software: string }> = {};
    for (const v of letter.vulnerabilities) {
      initial[v.id] = { action_type: v.action_type, software: v.software };
    }
    setDrafts(initial);
  }, [letter]);

  if (letter.vulnerabilities.length === 0) {
    return <Alert severity="info">Уязвимости не обнаружены</Alert>;
  }

  const updateDraft = (id: number, patch: Partial<{ action_type: string; software: string }>) => {
    setDrafts((prev) => ({ ...prev, [id]: { ...(prev[id] || { action_type: "", software: "" }), ...patch } }));
  };

  const handleSave = async (id: number) => {
    const d = drafts[id];
    if (!d) return;
    setSavingId(id);
    try {
      await lettersApi.updateVulnerability(letter.id, id, {
        action_type: d.action_type,
        software: d.software,
      });
      setSnack("Уязвимость сохранена");
      if (onSaved) onSaved();
    } catch (err: any) {
      setSnack("Ошибка: " + (err.response?.data?.detail || "неизвестная"));
    } finally {
      setSavingId(null);
    }
  };

  return (
    <Box>
      <Alert severity="info" sx={{ mb: 2 }}>
        Настройки применяются при генерации DOCX («Сгенерировать заново» на вкладке «Ответ»).
      </Alert>
      {letter.vulnerabilities.map((v) => {
        const d = drafts[v.id] || { action_type: v.action_type, software: v.software };
        const opt = actionTypeOptions.find((o) => o.value === d.action_type);
        return (
          <Card key={v.id} sx={{ mb: 2 }}>
            <CardContent>
              <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
                {v.bdu_id && <Chip label={v.bdu_id} size="small" color="info" />}
                {v.cve_id && <Chip label={v.cve_id} size="small" color="info" />}
                <Chip
                  label={severityLabels[v.severity] || v.severity}
                  size="small"
                  color={severityColors[v.severity] || "default"}
                />
              </Box>
              {v.description && (
                <Typography variant="body2" sx={{ mb: 2 }}>{v.description.slice(0, 300)}</Typography>
              )}
              <Grid container spacing={2}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    label="Программное обеспечение"
                    value={d.software}
                    onChange={(e) => updateDraft(v.id, { software: e.target.value })}
                    size="small"
                    fullWidth
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth size="small">
                    <Select
                      value={d.action_type}
                      onChange={(e) => updateDraft(v.id, { action_type: e.target.value })}
                    >
                      {actionTypeOptions.map((o) => (
                        <MenuItem key={o.value} value={o.value}>
                          {o.label}
                        </MenuItem>
                      ))}
                    </Select>
                    {opt && (
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                        {opt.desc}
                      </Typography>
                    )}
                  </FormControl>
                </Grid>
              </Grid>
              <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 2 }}>
                <Button
                  variant="contained"
                  size="small"
                  onClick={() => handleSave(v.id)}
                  disabled={savingId === v.id}
                >
                  {savingId === v.id ? "Сохранение..." : "Сохранить"}
                </Button>
              </Box>
            </CardContent>
          </Card>
        );
      })}
      <Snackbar
        open={!!snack}
        autoHideDuration={3000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const threatCutMarkers = [
  "Для предотвращения реализации угроз безопасности информации",
  "В целях предотвращения возможности эксплуатации указанной уязвимости",
  "В целях предотвращения возможности эксплуатации указанных уязвимостей",
  "В целях предотвращения реализации угроз безопасности информации",
];

function threatOnlyText(text: string): string {
  let cut = text.length;
  for (const m of threatCutMarkers) {
    const idx = text.indexOf(m);
    if (idx !== -1 && idx < cut) cut = idx;
  }
  const attachment = text.search(/[Вв]о\s+вложени/);
  if (attachment !== -1 && attachment < cut) cut = attachment;
  return text.slice(0, cut).replace(/\s+$/g, "");
}

function buildHighlightedHtml(text: string, iocs: IoCResponse[], measureOptions: string[]): string {
  const escaped = escapeHtml(text);
  const patterns: { re: RegExp; cls: string }[] = [];

  const hashIocs = iocs.filter((i) => i.ioc_type === "hash").map((i) => i.value);
  const ipIocs = iocs.filter((i) => i.ioc_type === "ip").map((i) => i.value);
  const domainIocs = iocs.filter((i) => i.ioc_type === "domain").map((i) => i.value);
  const emailIocs = iocs.filter((i) => i.ioc_type === "email").map((i) => i.value);

  for (const h of hashIocs) patterns.push({ re: new RegExp(h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-hash" });
  for (const ip of ipIocs) patterns.push({ re: new RegExp(ip.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-ip" });
  for (const d of domainIocs) patterns.push({ re: new RegExp(d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-domain" });
  for (const e of emailIocs) patterns.push({ re: new RegExp(e.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-email" });

  for (const measure of measureOptions) {
    if (measure.length > 15) {
      patterns.push({ re: new RegExp(measure.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), cls: "hl-measure" });
    }
  }

  const marks: { start: number; end: number; cls: string }[] = [];
  for (const { re, cls } of patterns) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(escaped)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      marks.push({ start: m.index, end: m.index + m[0].length, cls });
    }
  }
  marks.sort((a, b) => a.start - b.start || b.end - a.end);
  const filtered: typeof marks = [];
  let lastEnd = -1;
  for (const mk of marks) {
    if (mk.start >= lastEnd) {
      filtered.push(mk);
      lastEnd = mk.end;
    }
  }

  let result = "";
  let pos = 0;
  for (const mk of filtered) {
    result += escaped.slice(pos, mk.start);
    result += `<mark class="${mk.cls}">${escaped.slice(mk.start, mk.end)}</mark>`;
    pos = mk.end;
  }
  result += escaped.slice(pos);
  return result;
}

function ResponseTab({ letter, onGenerate }: { letter: LetterResponse; onGenerate: () => Promise<void> }) {
  const [preview, setPreview] = useState<{
    title: string;
    intro: string;
    sections: Array<{
      threat_id: number;
      number: number;
      prefix: string;
      description: string;
      measures: string[];
      measures_preview: string[];
      threat_type: string;
      measure_options: string[];
      intro_text: string;
      section_text: string;
    }>;
  } | null>(null);
  const [editText, setEditText] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [snack, setSnack] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const buildText = (data: typeof preview) => {
    if (!data) return "";
    const sections = data.sections.map((s) => {
      const intro = `${s.prefix}В целях предотвращения возможности реализации угроз безопасности информации, связанных с ${s.description}, приняты следующие меры защиты:`;
      const measures = (s.measures_preview ?? s.measures).map((m) => `\n  ${m}`).join("");
      return intro + measures;
    });
    return `${data.title}\n\n${data.intro}\n\n${sections.join("\n\n")}`;
  };

  const loadPreview = async () => {
    try {
      const { data } = await lettersApi.getResponsePreview(letter.id);
      setPreview(data);
      setEditText(buildText(data));
    } catch (err) {
      console.error(err?.message || "Error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadPreview(); }, [letter.id]);

  const handleGenerate = async () => {
    setLoading(true);
    await onGenerate();
    await loadPreview();
  };

  const handleDownloadDocx = async () => {
    try {
      const { data } = await lettersApi.download(letter.id);
      const url = URL.createObjectURL(data);
      const a = window.document.createElement("a");
      a.href = url;
      a.download = `Ответ на письмо ${letter.letter_number || letter.id}.docx`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err?.message || "Error");
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await lettersApi.updateResponse(letter.id, editText);
      setSnack("Сохранено");
    } catch (err) {
      setSnack("Ошибка сохранения");
    } finally {
      setSaving(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSnack("Скопировано");
  };

  const allMeasureOptions = preview
    ? preview.sections.flatMap((s) => s.measure_options)
    : [];

  const groupedTemplates = preview
    ? preview.sections.reduce(
        (acc, s) => {
          if (!acc[s.threat_type]) {
            acc[s.threat_type] = { type: s.threat_type, options: [] };
          }
          for (const opt of s.measure_options) {
            if (opt && !acc[s.threat_type].options.includes(opt)) {
              acc[s.threat_type].options.push(opt);
            }
          }
          return acc;
        },
        {} as Record<string, { type: string; options: string[] }>
      )
    : {};

  const renderIocGroup = (label: string, types: string[]) => {
    const items = letter.iocs.filter((i) => types.includes(i.ioc_type));
    if (items.length === 0) return null;
    return (
      <Box sx={{ mb: 1.5 }}>
        <Typography variant="caption" sx={{ fontWeight: "bold", display: "block", mb: 0.5, textTransform: "uppercase", color: "text.secondary" }}>
          {label} ({items.length})
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
          {items.map((ioc) => (
            <Chip
              key={ioc.id}
              label={ioc.value.length > 30 ? ioc.value.slice(0, 30) + "..." : ioc.value}
              size="small"
              color={iocChipColors[ioc.ioc_type] || "default"}
              onClick={() => copyToClipboard(ioc.value)}
              title={`Кликнуть чтобы скопировать: ${ioc.value}`}
              sx={{ cursor: "pointer", fontFamily: "monospace", fontSize: "0.7rem" }}
            />
          ))}
        </Box>
      </Box>
    );
  };

  if (loading) return <Typography>Загрузка...</Typography>;

  return (
    <Box>
      <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
        <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleGenerate}>
          Сгенерировать заново
        </Button>
        <Button variant="contained" startIcon={<DownloadIcon />} onClick={handleDownloadDocx} disabled={!preview}>
          Скачать DOCX
        </Button>
        <Button variant="outlined" onClick={handleSave} disabled={!preview}>
          {saving ? "Сохранение..." : "Сохранить"}
        </Button>
      </Box>

      {!preview ? (
        <Alert severity="info">Нажмите «Сгенерировать заново» для создания ответа</Alert>
      ) : (
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, md: 8 }}>
            <Paper
              variant="outlined"
              sx={{
                position: "relative",
                fontFamily: "Times New Roman, serif",
                fontSize: "0.9rem",
                lineHeight: 1.5,
                "& mark": { borderRadius: "2px", padding: "0 1px" },
                "& .hl-hash": { backgroundColor: "#fff3bf" },
                "& .hl-ip": { backgroundColor: "#d0ebff" },
                "& .hl-domain": { backgroundColor: "#d3f9d8" },
                "& .hl-email": { backgroundColor: "#ffec99" },
                "& .hl-measure": { backgroundColor: "#e7f5ff", borderBottom: "1px dashed #1976d2" },
                "& textarea::selection": { backgroundColor: "rgba(25, 118, 210, 0.3)" },
              }}
            >
              <Box
                aria-hidden
                component="pre"
                sx={{
                  position: "absolute",
                  top: 0, left: 0, right: 0, bottom: 0,
                  margin: 0, padding: "16px",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  pointerEvents: "none",
                  overflow: "auto",
                  fontFamily: "inherit",
                  fontSize: "inherit",
                  lineHeight: "inherit",
                  color: "#000",
                }}
                dangerouslySetInnerHTML={{ __html: buildHighlightedHtml(editText, letter.iocs, allMeasureOptions) + "\n" }}
              />
              <textarea
                ref={textareaRef}
                value={editText}
                onChange={(e) => setEditText(e.target.value)}
                onScroll={(e) => {
                  const ta = e.currentTarget;
                  const pre = ta.previousElementSibling;
                  if (pre) {
                    pre.scrollTop = ta.scrollTop;
                    pre.scrollLeft = ta.scrollLeft;
                  }
                }}
                spellCheck={false}
                style={{
                  position: "relative",
                  display: "block",
                  width: "100%",
                  minHeight: "60vh",
                  padding: "16px",
                  margin: 0,
                  border: "none",
                  outline: "none",
                  resize: "vertical",
                  background: "transparent",
                  color: "transparent",
                  caretColor: "#000",
                  fontFamily: "inherit",
                  fontSize: "inherit",
                  lineHeight: "inherit",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  overflow: "auto",
                  WebkitTextFillColor: "transparent",
                }}
              />
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, md: 4 }}>
            <Box sx={{ position: "sticky", top: 16, maxHeight: "calc(100vh - 100px)", overflowY: "auto" }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Шаблоны мер (клик — копировать)
              </Typography>
              {Object.entries(groupedTemplates).map(([type, group]) => (
                <Accordion key={type} defaultExpanded={Object.keys(groupedTemplates).length === 1} disableGutters sx={{ mb: 0.5, "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ minHeight: 36, "& .MuiAccordionSummary-content": { m: 0 } }}>
                    <Typography variant="body2" sx={{ fontWeight: "medium" }}>
                      {threatTypeLabels[type] || type} ({group.options.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ p: 1, pt: 0.5 }}>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                      {group.options.map((opt) => (
                        <Button
                          key={opt}
                          size="small"
                          variant="text"
                          sx={{
                            textAlign: "left",
                            justifyContent: "flex-start",
                            fontSize: "0.72rem",
                            textTransform: "none",
                            whiteSpace: "normal",
                            wordBreak: "break-word",
                            p: 0.5,
                            lineHeight: 1.3,
                            color: "text.primary",
                          }}
                          onClick={() => copyToClipboard(opt)}
                          title={opt}
                        >
                          {opt}
                        </Button>
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                IoC ({letter.iocs.length}) — клик копирует
              </Typography>
              {renderIocGroup("IP-адреса", ["ip"])}
              {renderIocGroup("Домены", ["domain"])}
              {renderIocGroup("Хэши", ["hash"])}
              {renderIocGroup("Email", ["email"])}
              {renderIocGroup("BDU", ["bdu"])}
              {renderIocGroup("CVE", ["cve"])}
              {letter.iocs.length === 0 && (
                <Typography variant="caption" color="text.secondary">Нет IoC</Typography>
              )}
            </Box>
          </Grid>
        </Grid>
      )}

      <Snackbar
        open={!!snack}
        autoHideDuration={2000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </Box>
  );
}

function ExportTab({ onExport, onExportDocx, counts }: { onExport: (type: string) => void; onExportDocx: (type: string) => void; counts: IoCResponse[] }) {
  const exportTypes = [
    { type: "emails", label: "Email-адреса", count: counts.filter((i) => i.ioc_type === "email").length },
    { type: "ip_addresses", label: "IP-адреса (на блокировку)", count: counts.filter((i) => i.ioc_type === "ip").length },
    { type: "domains", label: "Домены (на блокировку)", count: counts.filter((i) => i.ioc_type === "domain").length },
    { type: "ioc_indicators", label: "Все IOC (IP + домены + хэши + email + BDU + CVE)", count: counts.length },
  ];

  return (
    <Box>
      <Typography variant="subtitle1" gutterBottom>Экспорт IOC-файлов</Typography>
      <Grid container spacing={2}>
        {exportTypes.map((et) => (
          <Grid size={{ xs: 12, md: 6 }} key={et.type}>
            <Card>
              <CardContent>
                <Typography variant="subtitle2">{et.label}</Typography>
                <Typography variant="h6" color="primary">{et.count} записей</Typography>
                <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
                  <Button
                    variant="contained"
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => onExportDocx(et.type)}
                    disabled={et.count === 0}
                  >
                    DOCX
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => onExport(et.type)}
                    disabled={et.count === 0}
                  >
                    TXT
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}
