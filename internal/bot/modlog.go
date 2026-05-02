package bot

import (
	"fmt"
	"log"

	"odysseyshield/internal/filter"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// sendModLog posts a moderation event to the configured log channel.
// Callback data fits within Telegram's 64-byte limit:
//
//	res|<chatID>|<msgID>|<userID>  ≤ 45 chars
//	mut|<chatID>|<userID>          ≤ 29 chars
//	ban|<chatID>|<userID>          ≤ 29 chars
func (b *Bot) sendModLog(
	chatID int64,
	msgID int,
	userID int64,
	username, text, reason string,
	score int,
	action filter.Action,
) {
	if b.cfg.LogChannelID == 0 {
		return
	}

	emoji, actionLabel := actionMeta(action)

	body := fmt.Sprintf(
		"%s <b>Odyssey Shield</b> — %s\n\n"+
			"👤 <b>Пользователь:</b> %s (<code>%d</code>)\n"+
			"📊 <b>Риск-балл:</b> %d\n"+
			"🔍 <b>Причины:</b> <code>%s</code>\n\n"+
			"💬 <b>Сообщение:</b>\n"+
			"<blockquote>%s</blockquote>",
		emoji, actionLabel,
		escapeHTML(username), userID,
		score,
		escapeHTML(reason),
		escapeHTML(truncate(text, 400)),
	)

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(
				"✅ Восстановить",
				fmt.Sprintf("res|%d|%d|%d", chatID, msgID, userID),
			),
			tgbotapi.NewInlineKeyboardButtonData(
				"🔇 Мут 24ч",
				fmt.Sprintf("mut|%d|%d", chatID, userID),
			),
			tgbotapi.NewInlineKeyboardButtonData(
				"🚫 Бан",
				fmt.Sprintf("ban|%d|%d", chatID, userID),
			),
		),
	)

	msg := tgbotapi.NewMessage(b.cfg.LogChannelID, body)
	msg.ParseMode = "HTML"
	msg.ReplyMarkup = keyboard

	if _, err := b.api.Send(msg); err != nil {
		log.Printf("sendModLog: %v", err)
	}
}

func actionMeta(a filter.Action) (emoji, label string) {
	switch a {
	case filter.ActionWarn:
		return "⚠️", "Предупреждение (удалено)"
	case filter.ActionMute:
		return "🔇", "Мут 24ч"
	case filter.ActionBan:
		return "🚫", "Бан"
	default:
		return "ℹ️", "Информация"
	}
}
