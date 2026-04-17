package bot

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"odysseyshield/internal/filter"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// ── Router ────────────────────────────────────────────────────────

func (b *Bot) handleUpdate(upd tgbotapi.Update) {
	switch {
	case upd.Message != nil:
		b.handleMessage(upd.Message)
	case upd.CallbackQuery != nil:
		b.handleCallback(upd.CallbackQuery)
	}
}

// ── Message handler ───────────────────────────────────────────────

func (b *Bot) handleMessage(msg *tgbotapi.Message) {
	// Skip channel posts and anonymous-admin messages (SenderChat set, From nil or bot).
	if msg.From == nil {
		return
	}
	if msg.SenderChat != nil {
		return
	}

	userID := msg.From.ID
	chatID := msg.Chat.ID

	// Trusted users bypass all filters (by ID or username).
	if b.cfg.IsTrustedUser(userID) || b.cfg.IsTrustedUsername(msg.From.UserName) {
		b.store.IncrementMessageCount(userID)
		return
	}

	// Chat admins bypass all filters (cached check).
	if b.isAdmin(chatID, userID) {
		b.store.IncrementMessageCount(userID)
		return
	}

	result := b.filter.Analyze(msg)

	// Always count the message regardless of outcome.
	defer b.store.IncrementMessageCount(userID)

	if result.Action == filter.ActionNone {
		return
	}

	text := messageText(msg)
	username := displayName(msg.From)
	reason := fmt.Sprintf("score=%d reasons=[%s]", result.Score, strings.Join(result.Reasons, ", "))

	b.store.SaveDeleted(chatID, msg.MessageID, userID, username, truncate(text, 300), reason, result.Score)
	b.deleteMessage(chatID, msg.MessageID)

	switch result.Action {
	case filter.ActionWarn:
		b.sendTempWarning(chatID, msg.From)
		b.sendModLog(chatID, msg.MessageID, userID, username, text, reason, result.Score, result.Action)

	case filter.ActionMute:
		b.muteUser(chatID, userID, b.cfg.MuteDuration)
		b.sendModLog(chatID, msg.MessageID, userID, username, text, reason, result.Score, result.Action)

	case filter.ActionBan:
		b.banUser(chatID, userID)
		b.sendModLog(chatID, msg.MessageID, userID, username, text, reason, result.Score, result.Action)
	}
}

// ── Callback handler ──────────────────────────────────────────────

// Callback data format:
//   res|<chatID>|<msgID>|<userID>   — restore (unban/unmute)
//   mut|<chatID>|<userID>           — mute 24 h
//   ban|<chatID>|<userID>           — ban

func (b *Bot) handleCallback(cb *tgbotapi.CallbackQuery) {
	parts := strings.Split(cb.Data, "|")
	if len(parts) < 3 {
		b.answerCallback(cb.ID, "❌ Неверный формат")
		return
	}

	action := parts[0]

	chatID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		b.answerCallback(cb.ID, "❌ Неверный chatID")
		return
	}

	moderatorName := displayName(cb.From)

	switch action {
	case "res":
		if len(parts) < 4 {
			b.answerCallback(cb.ID, "❌ Ошибка")
			return
		}
		msgID, e1 := strconv.Atoi(parts[2])
		targetUserID, e2 := strconv.ParseInt(parts[3], 10, 64)
		if e1 != nil || e2 != nil {
			b.answerCallback(cb.ID, "❌ Ошибка данных")
			return
		}

		b.unbanUser(chatID, targetUserID)

		var userRef string
		if deleted, ok := b.store.GetDeleted(chatID, msgID); ok {
			userRef = escapeHTML(deleted.Username)
		} else {
			userRef = fmt.Sprintf("id%d", targetUserID)
		}
		suffix := fmt.Sprintf("\n\n✅ <b>Восстановлен</b> %s — модератор %s", userRef, escapeHTML(moderatorName))
		b.appendToLogMessage(cb, suffix)
		b.answerCallback(cb.ID, "✅ Пользователь восстановлен")

	case "mut":
		targetUserID, e := strconv.ParseInt(parts[2], 10, 64)
		if e != nil {
			b.answerCallback(cb.ID, "❌ Ошибка данных")
			return
		}

		b.muteUser(chatID, targetUserID, b.cfg.MuteDuration)

		suffix := fmt.Sprintf("\n\n🔇 <b>Замучен 24ч</b> модератором %s", escapeHTML(moderatorName))
		b.appendToLogMessage(cb, suffix)
		b.answerCallback(cb.ID, "🔇 Пользователь замучен")

	case "ban":
		targetUserID, e := strconv.ParseInt(parts[2], 10, 64)
		if e != nil {
			b.answerCallback(cb.ID, "❌ Ошибка данных")
			return
		}

		b.banUser(chatID, targetUserID)

		suffix := fmt.Sprintf("\n\n🚫 <b>Забанен</b> модератором %s", escapeHTML(moderatorName))
		b.appendToLogMessage(cb, suffix)
		b.answerCallback(cb.ID, "🚫 Пользователь забанен")

	default:
		b.answerCallback(cb.ID, "❌ Неизвестное действие")
	}

}

// ── Telegram API wrappers ─────────────────────────────────────────

func (b *Bot) isAdmin(chatID, userID int64) bool {
	if isAdmin, ok := b.store.GetAdminCache(chatID, userID); ok {
		return isAdmin
	}
	member, err := b.api.GetChatMember(tgbotapi.GetChatMemberConfig{
		ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
			ChatID: chatID,
			UserID: userID,
		},
	})
	if err != nil {
		log.Printf("GetChatMember(%d, %d): %v", chatID, userID, err)
		return false
	}
	admin := member.Status == "creator" || member.Status == "administrator"
	b.store.SetAdminCache(chatID, userID, admin)
	return admin
}

func (b *Bot) deleteMessage(chatID int64, msgID int) {
	if _, err := b.api.Request(tgbotapi.NewDeleteMessage(chatID, msgID)); err != nil {
		log.Printf("deleteMessage(%d, %d): %v", chatID, msgID, err)
	}
}

func (b *Bot) muteUser(chatID, userID int64, durationSec int) {
	until := time.Now().Add(time.Duration(durationSec) * time.Second)
	cfg := tgbotapi.RestrictChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		UntilDate: until.Unix(),
		Permissions: &tgbotapi.ChatPermissions{
			CanSendMessages:      false,
			CanSendMediaMessages: false,
			CanSendPolls:         false,
			CanSendOtherMessages: false,
		},
	}
	if _, err := b.api.Request(cfg); err != nil {
		log.Printf("muteUser(%d, %d): %v", chatID, userID, err)
	}
	b.store.SetMuted(userID, until)
}

func (b *Bot) banUser(chatID, userID int64) {
	cfg := tgbotapi.BanChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		RevokeMessages: true,
	}
	if _, err := b.api.Request(cfg); err != nil {
		log.Printf("banUser(%d, %d): %v", chatID, userID, err)
	}
	b.store.SetBanned(userID)
}

func (b *Bot) unbanUser(chatID, userID int64) {
	cfg := tgbotapi.UnbanChatMemberConfig{
		ChatMemberConfig: tgbotapi.ChatMemberConfig{
			ChatID: chatID,
			UserID: userID,
		},
		OnlyIfBanned: false, // also lifts restrictions
	}
	if _, err := b.api.Request(cfg); err != nil {
		log.Printf("unbanUser(%d, %d): %v", chatID, userID, err)
	}
}

func (b *Bot) sendTempWarning(chatID int64, from *tgbotapi.User) {
	name := displayName(from)
	msg := tgbotapi.NewMessage(chatID,
		fmt.Sprintf("⚠️ Сообщение от %s было удалено. Соблюдайте правила чата.", name),
	)
	sent, err := b.api.Send(msg)
	if err != nil {
		log.Printf("sendTempWarning: %v", err)
		return
	}
	go func() {
		time.Sleep(30 * time.Second)
		b.deleteMessage(chatID, sent.MessageID)
	}()
}

func (b *Bot) answerCallback(id, text string) {
	if _, err := b.api.Request(tgbotapi.NewCallback(id, text)); err != nil {
		log.Printf("answerCallback: %v", err)
	}
}

// appendToLogMessage appends suffix to the existing log message text and
// removes the inline keyboard (action already taken).
func (b *Bot) appendToLogMessage(cb *tgbotapi.CallbackQuery, suffix string) {
	if cb.Message == nil {
		return
	}
	logChatID := cb.Message.Chat.ID
	logMsgID := cb.Message.MessageID

	newText := cb.Message.Text + suffix
	edit := tgbotapi.NewEditMessageText(logChatID, logMsgID, newText)
	edit.ParseMode = "HTML"
	empty := tgbotapi.NewInlineKeyboardMarkup()
	edit.ReplyMarkup = &empty

	if _, err := b.api.Send(edit); err != nil {
		log.Printf("appendToLogMessage: %v", err)
	}
}

// ── Utility ───────────────────────────────────────────────────────

func messageText(msg *tgbotapi.Message) string {
	if msg.Text != "" {
		return msg.Text
	}
	return msg.Caption
}

func displayName(u *tgbotapi.User) string {
	if u == nil {
		return "unknown"
	}
	if u.UserName != "" {
		return "@" + u.UserName
	}
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name == "" {
		return fmt.Sprintf("id%d", u.ID)
	}
	return name
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
