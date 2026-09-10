import { useState, useRef, useCallback } from "react";
import {
  Box,
  Paper,
  Button,
  Typography,
  List,
  ListItem,
  ListItemText,
  IconButton,
  LinearProgress,
  Alert,
  Grid,
} from "@mui/material";
import {
  CloudUpload as UploadIcon,
  Delete as DeleteIcon,
  Description as FileIcon,
} from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { lettersApi } from "../api/client";

const MAX_FILES = 10;

export default function Upload() {
  const navigate = useNavigate();
  const [files, setFiles] = useState<File[]>([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback((incoming: FileList | File[] | null) => {
    if (!incoming || incoming.length === 0) return;
    setError("");
    const arr = Array.from(incoming);
    const next = [...files, ...arr].slice(-MAX_FILES);
    setFiles(next);
    if (files.length + arr.length > MAX_FILES) {
      setError(`Максимум ${MAX_FILES} файлов за раз`);
    }
  }, [files]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    addFiles(e.dataTransfer.files);
  }, [addFiles]);

  const handleUpload = async () => {
    if (files.length === 0) {
      setError("Выберите хотя бы один файл");
      return;
    }
    setUploading(true);
    setError("");
    try {
      const { data } = await lettersApi.upload(files);
      navigate(`/letters/${data.id}`);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка загрузки");
    } finally {
      setUploading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h5" gutterBottom>Загрузка документов</Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {uploading && <LinearProgress sx={{ mb: 2 }} />}

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 8, lg: 6 }}>
          <Paper
            sx={{
              p: 4,
              textAlign: "center",
              border: "2px dashed",
              borderColor: dragOver ? "primary.main" : files.length ? "success.main" : "divider",
              backgroundColor: dragOver ? "action.hover" : "transparent",
              cursor: "pointer",
              mb: 2,
            }}
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
          >
            <input
              ref={inputRef}
              type="file"
              multiple
              hidden
              onChange={(e) => { addFiles(e.target.files); e.target.value = ""; }}
            />
            <UploadIcon sx={{ fontSize: 48, color: dragOver ? "primary.main" : "text.secondary", mb: 1 }} />
            <Typography variant="body1" color="text.secondary">
              Перетащите файлы сюда или нажмите для выбора
            </Typography>
            <Typography variant="caption" color="text.secondary">
              PDF, DOC, DOCX, XLSX, TXT, EML, HTML, RTF и другие форматы · до {MAX_FILES} файлов · до 20 МБ каждый
            </Typography>
          </Paper>

          <Paper sx={{ p: 3, mb: 2 }}>
            <Typography variant="subtitle1" gutterBottom>
              Файлы пакета ({files.length} из {MAX_FILES})
            </Typography>
            <List dense>
              {files.map((f, i) => (
                <ListItem
                  key={`${f.name}-${i}`}
                  secondaryAction={
                    <IconButton edge="end" onClick={() => setFiles((prev) => prev.filter((_, idx) => idx !== i))}>
                      <DeleteIcon />
                    </IconButton>
                  }
                >
                  <FileIcon sx={{ mr: 1, color: "text.secondary" }} />
                  <ListItemText primary={f.name} secondary={`${(f.size / 1024).toFixed(0)} KB`} />
                </ListItem>
              ))}
              {files.length === 0 && (
                <Typography variant="body2" color="text.secondary">Файлы не выбраны</Typography>
              )}
            </List>
          </Paper>

          <Button
            variant="contained"
            size="large"
            fullWidth
            disabled={files.length === 0 || uploading}
            onClick={handleUpload}
            startIcon={<UploadIcon />}
          >
            {uploading ? "Загрузка..." : "Загрузить и обработать"}
          </Button>
        </Grid>
      </Grid>
    </Box>
  );
}
