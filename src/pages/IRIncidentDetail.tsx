import React, { useEffect, useState } from "react";
import { saveAs } from "file-saver";
import { useNavigate, useParams } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { IRIncidentDetailWorkspace } from "@/features/ir/components/IRIncidentDetailWorkspace";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";

export default function IRIncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [loading, setLoading] = useState(false);
  const [incident, setIncident] = useState<any | null>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [saving, setSaving] = useState(false);

  const [patch, setPatch] = useState({
    status: "NEW",
    severity: "MEDIUM",
    priority: "P3",
    assignedToUserId: "unassigned",
    internalNotes: "",
    tags: "",
    resolutionSummary: "",
    resolutionOutcome: "none",
  });

  const [newNote, setNewNote] = useState("");
  const [emailSubject, setEmailSubject] = useState("Update on your incident");
  const [emailBody, setEmailBody] = useState("");
  const [emailRecipient, setEmailRecipient] = useState<"reporter" | "org_admin">("reporter");
  const [sendingEmail, setSendingEmail] = useState(false);
  const [lastEmailDelivery, setLastEmailDelivery] = useState<{
    delivered: boolean;
    providerMessageId?: string | null;
    attemptedFrom?: string | null;
    usedFrom?: string | null;
    replyTo?: string | null;
    error?: string | null;
  } | null>(null);

  const [uploading, setUploading] = useState(false);
  const [attachmentFile, setAttachmentFile] = useState<File | null>(null);

  const [actionDialog, setActionDialog] = useState<{
    open: boolean;
    action:
      | "FLAG_QR_UNDER_INVESTIGATION"
      | "UNFLAG_QR_UNDER_INVESTIGATION"
      | "SUSPEND_BATCH"
      | "REINSTATE_BATCH"
      | "SUSPEND_ORG"
      | "REINSTATE_ORG"
      | "SUSPEND_MANUFACTURER_USERS"
      | "REINSTATE_MANUFACTURER_USERS"
      | null;
    reason: string;
  }>({ open: false, action: null, reason: "" });
  const [applyingAction, setApplyingAction] = useState(false);
  const [trustReview, setTrustReview] = useState({
    credentialId: "",
    reviewState: "VERIFIED",
    reviewNote: "",
  });
  const [reviewingTrust, setReviewingTrust] = useState(false);

  const load = async () => {
    if (!id) return;
    setLoading(true);
    try {
      const response = await apiClient.getIrIncidentById(id);
      if (!response.success) {
        setIncident(null);
        toast({ title: "Load failed", description: response.error || "Could not load incident.", variant: "destructive" });
        return;
      }
      const data: any = response.data;
      setIncident(data);
      setLastEmailDelivery(null);
      const trustCredentials = Array.isArray(data?.customerTrustCredentials) ? data.customerTrustCredentials : [];
      setTrustReview((previous) => ({
        credentialId:
          trustCredentials.some((row: any) => row.id === previous.credentialId)
            ? previous.credentialId
            : String(trustCredentials[0]?.id || ""),
        reviewState: previous.reviewState || "VERIFIED",
        reviewNote: previous.reviewNote || "",
      }));
      setPatch({
        status: data.status || "NEW",
        severity: data.severity || "MEDIUM",
        priority: data.priority || "P3",
        assignedToUserId: data.assignedToUserId || "unassigned",
        internalNotes: data.internalNotes || "",
        tags: Array.isArray(data.tags) ? data.tags.join(", ") : "",
        resolutionSummary: data.resolutionSummary || "",
        resolutionOutcome: data.resolutionOutcome || "none",
      });
      setEmailBody(`We are reviewing your report${data?.id ? ` (${data.id})` : ""}. If we need more information, we will contact you.`);
    } finally {
      setLoading(false);
    }
  };

  const loadUsers = async () => {
    const response = await apiClient.getUsers();
    if (!response.success) return;
    const list = (response.data as any[]) || [];
    setUsers(list.filter((user) => String(user.role || "").toUpperCase().includes("SUPER_ADMIN")));
  };

  useEffect(() => {
    void load();
    void loadUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const savePatch = async () => {
    if (!id || !incident) return;
    setSaving(true);
    try {
      const payload: any = {
        status: patch.status,
        severity: patch.severity,
        priority: patch.priority,
        assignedToUserId: patch.assignedToUserId !== "unassigned" ? patch.assignedToUserId : null,
        internalNotes: patch.internalNotes || null,
        resolutionSummary: patch.resolutionSummary || null,
        resolutionOutcome: patch.resolutionOutcome !== "none" ? patch.resolutionOutcome : null,
        tags: patch.tags.split(",").map((segment) => segment.trim()).filter(Boolean),
      };

      const response = await apiClient.patchIrIncident(id, payload);
      if (!response.success) {
        toast({ title: "Save failed", description: response.error || "Could not save incident.", variant: "destructive" });
        return;
      }
      toast({ title: "Saved", description: "Incident updated." });
      await load();
    } finally {
      setSaving(false);
    }
  };

  const addNote = async () => {
    if (!id) return;
    const note = newNote.trim();
    if (note.length < 2) return;
    const response = await apiClient.addIrIncidentNote(id, note);
    if (!response.success) {
      toast({ title: "Note failed", description: response.error || "Could not add note.", variant: "destructive" });
      return;
    }
    setNewNote("");
    await load();
  };

  const sendEmail = async () => {
    if (!id) return;
    if (emailSubject.trim().length < 3 || emailBody.trim().length < 1) {
      toast({ title: "Missing message", description: "Subject and message are required.", variant: "destructive" });
      return;
    }

    setSendingEmail(true);
    try {
      const response = await apiClient.sendIrIncidentCommunication(id, {
        recipient: emailRecipient,
        subject: emailSubject.trim(),
        message: emailBody.trim(),
        template: "ir_manual",
        senderMode: "system",
      });
      const delivery = (response.data || {}) as any;
      setLastEmailDelivery({
        delivered: Boolean(delivery?.delivered ?? response.success),
        providerMessageId: delivery?.providerMessageId || null,
        attemptedFrom: delivery?.attemptedFrom || null,
        usedFrom: delivery?.usedFrom || null,
        replyTo: delivery?.replyTo || null,
        error: delivery?.error || (response.success ? null : response.error || "Email delivery failed"),
      });
      if (!response.success) {
        toast({ title: "Send failed", description: response.error || "Could not send email.", variant: "destructive" });
        return;
      }
      toast({
        title: "Email sent",
        description: `Delivered via ${delivery?.usedFrom || delivery?.attemptedFrom || "configured SMTP sender"}.`,
      });
      await load();
    } finally {
      setSendingEmail(false);
    }
  };

  const uploadAttachment = async () => {
    if (!id || !attachmentFile) return;
    setUploading(true);
    try {
      const response = await apiClient.uploadIrIncidentAttachment(id, attachmentFile);
      if (!response.success) {
        toast({ title: "Upload failed", description: response.error || "Could not upload.", variant: "destructive" });
        return;
      }
      toast({ title: "Uploaded", description: "Attachment added to the incident." });
      setAttachmentFile(null);
      await load();
    } finally {
      setUploading(false);
    }
  };

  const downloadEvidence = async (storageKey: string) => {
    try {
      const blob = await apiClient.downloadIncidentEvidence(storageKey);
      saveAs(blob, storageKey);
    } catch (error: any) {
      toast({ title: "Download failed", description: error?.message || "Could not download file.", variant: "destructive" });
    }
  };

  const applyAction = async () => {
    if (!id || !actionDialog.action) return;
    const reason = actionDialog.reason.trim();
    if (reason.length < 3) {
      toast({ title: "Reason required", description: "Add a short reason (min 3 characters).", variant: "destructive" });
      return;
    }

    setApplyingAction(true);
    try {
      const payload: any = { action: actionDialog.action, reason };
      if (incident?.qrCode?.id) payload.qrCodeId = incident.qrCode.id;
      if (incident?.qrCode?.batch?.id) payload.batchId = incident.qrCode.batch.id;
      if (incident?.licenseeId) payload.licenseeId = incident.licenseeId;

      const response = await apiClient.applyIrIncidentAction(id, payload);
      if (!response.success) {
        toast({ title: "Action failed", description: response.error || "Could not apply containment action.", variant: "destructive" });
        return;
      }
      toast({ title: "Action applied", description: "Containment action recorded." });
      setActionDialog({ open: false, action: null, reason: "" });
      await load();
    } finally {
      setApplyingAction(false);
    }
  };

  const applyTrustReview = async () => {
    if (!id || !trustReview.credentialId) {
      toast({ title: "Select a trust record", description: "Choose a customer trust record first.", variant: "destructive" });
      return;
    }

    setReviewingTrust(true);
    try {
      const response = await apiClient.reviewIrIncidentCustomerTrust(id, {
        credentialId: trustReview.credentialId,
        reviewState: trustReview.reviewState as "UNREVIEWED" | "VERIFIED" | "DISPUTED" | "REVOKED",
        reviewNote: trustReview.reviewNote.trim() || undefined,
      });
      if (!response.success) {
        toast({ title: "Trust review failed", description: response.error || "Could not update trust review.", variant: "destructive" });
        return;
      }
      toast({ title: "Trust review updated", description: "Customer trust state was updated for this incident QR." });
      setTrustReview((previous) => ({ ...previous, reviewNote: "" }));
      await load();
    } finally {
      setReviewingTrust(false);
    }
  };

  if (!id) {
    return (
      <DashboardLayout>
        <div className="rounded-lg border p-6 text-sm text-muted-foreground">Missing incident id.</div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <IRIncidentDetailWorkspace
        id={id}
        loading={loading}
        incident={incident}
        users={users}
        saving={saving}
        patch={patch}
        onPatchChange={setPatch}
        onSavePatch={savePatch}
        onLoad={load}
        onNavigateBack={() => navigate("/ir")}
        newNote={newNote}
        onNewNoteChange={setNewNote}
        onAddNote={addNote}
        emailSubject={emailSubject}
        onEmailSubjectChange={setEmailSubject}
        emailBody={emailBody}
        onEmailBodyChange={setEmailBody}
        emailRecipient={emailRecipient}
        onEmailRecipientChange={setEmailRecipient}
        sendingEmail={sendingEmail}
        onSendEmail={sendEmail}
        lastEmailDelivery={lastEmailDelivery}
        uploading={uploading}
        attachmentFile={attachmentFile}
        onAttachmentFileChange={setAttachmentFile}
        onUploadAttachment={uploadAttachment}
        onDownloadEvidence={downloadEvidence}
        onOpenAction={(action) => setActionDialog({ open: true, action, reason: "" })}
        actionDialog={actionDialog}
        onActionDialogChange={setActionDialog}
        applyingAction={applyingAction}
        onApplyAction={applyAction}
        trustReview={trustReview}
        onTrustReviewChange={setTrustReview}
        reviewingTrust={reviewingTrust}
        onApplyTrustReview={applyTrustReview}
      />
    </DashboardLayout>
  );
}
