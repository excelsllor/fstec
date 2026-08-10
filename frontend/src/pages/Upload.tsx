import { useState, useRef } from "react";
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

export default function Upload() {
  const navigate = useNavigate();
  const [mainFile, setMainFile] = useState<File | null>(null);
  const [attachments, setAttachments] = useState<File[]>([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const attInputRef = useRef<HTMLInputElement>(null);

  const handleMainSelect = (files: FileList | null) => {
    if (files && files[0]) {
      setError("");
      setMainFile(files[0]);
    }
  };

  const handleAttSelect = (files: FileList | null) => {
    if (files) {
      setAttachments((prev) => [...prev, ...Array.from(files)]);
    }
  };

  const handleUpload = async () => {
    if (!mainFile) {
      setError("Выберите основной файл");
      return;
    }
    setUploading(true);
    setError("");
    try {
      const { data } = await lettersApi.upload(mainFile, attachments);
      navigate(`/letters/${data.id}`);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Ошибка загрузки");
    } finally {
      setUploading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h5" gutterBottom>Загрузка письма</Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {uploading && <LinearProgress sx={{ mb: 2 }} />}

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 8, lg: 6 }}>
          <Paper
            sx={{
              p: 4,
              textAlign: "center",
              border: "2px dashed",
              borderColor: mainFile ? "success.main" : "divider",
              cursor: "pointer",
              mb: 2,
            }}
            onClick={() => inputRef.current?.click()}
          >
            <input
              ref={inputRef}
              type="file"
              hidden
              onChange={(e) => handleMainSelect(e.target.files)}
            />
            {mainFile ? (
              <Box>
                <FileIcon sx={{ fontSize: 48, color: "success.main", mb: 1 }} />
                <Typography variant="body1">{mainFile.name}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {(mainFile.size / 1024).toFixed(0)} KB
                </Typography>
              </Box>
            ) : (
              <Box>
                <UploadIcon sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
                <Typography variant="body1" color="text.secondary">
                  Нажмите для выбора основного файла
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  PDF, DOC, DOCX, TXT, EML, HTML, RTF и другие форматы
                </Typography>
              </Box>
            )}
          </Paper>

          <Paper sx={{ p: 3, mb: 2 }}>
            <Typography variant="subtitle1" gutterBottom>Вложения (любые форматы)</Typography>
            <Button
              variant="outlined"
              startIcon={<UploadIcon />}
              onClick={() => attInputRef.current?.click()}
              sx={{ mb: 2 }}
            >
              Добавить вложения
            </Button>
            <input
              ref={attInputRef}
              type="file"
              multiple
              hidden
              onChange={(e) => handleAttSelect(e.target.files)}
            />
            <List dense>
              {attachments.map((f, i) => (
                <ListItem
                  key={i}
                  secondaryAction={
                    <IconButton edge="end" onClick={() => setAttachments((prev) => prev.filter((_, idx) => idx !== i))}>
                      <DeleteIcon />
                    </IconButton>
                  }
                >
                  <FileIcon sx={{ mr: 1, color: "text.secondary" }} />
                  <ListItemText primary={f.name} secondary={`${(f.size / 1024).toFixed(0)} KB`} />
                </ListItem>
              ))}
              {attachments.length === 0 && (
                <Typography variant="body2" color="text.secondary">Нет вложений</Typography>
              )}
            </List>
          </Paper>

          <Button
            variant="contained"
            size="large"
            fullWidth
            disabled={!mainFile || uploading}
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
