package filter

import "regexp"

// WeightedPattern pairs a compiled regexp with its risk weight and label.
type WeightedPattern struct {
	Re     *regexp.Regexp
	Weight int
	Label  string
}

func p(pattern string, weight int, label string) WeightedPattern {
	return WeightedPattern{
		Re:     regexp.MustCompile(`(?i)` + pattern),
		Weight: weight,
		Label:  label,
	}
}

// VPN and proxy promotion.
var VPNPatterns = []WeightedPattern{
	p(`\bvpn\b`, 15, "vpn"),
	p(`nordvpn|expressvpn|surfshark`, 20, "vpn_brand"),
	p(`\bпрокси\b`, 15, "proxy"),
	p(`обход.{0,10}блокировок`, 20, "bypass"),
	p(`анонимайзер`, 15, "anonymizer"),
	p(`скрыть.{0,5}ip`, 20, "hide_ip"),
	p(`\bproxy\b`, 15, "proxy_en"),
	p(`защищённ|безопасный интернет`, 10, "secure_web"),
}

// Phishing / channel-migration spam.
var PhishingPatterns = []WeightedPattern{
	p(`мы переезжаем`, 30, "migration"),
	p(`новый.{0,10}чат`, 25, "new_chat"),
	p(`переходите.{0,15}ссылк`, 25, "follow_link"),
	p(`срочно.{0,10}перейти`, 30, "urgent_link"),
	p(`новая.{0,5}ссылка`, 25, "new_link"),
	p(`канал.{0,10}переезжа`, 30, "channel_move"),
	p(`перенос.{0,10}канала`, 30, "channel_transfer"),
	p(`подписывайтесь.{0,20}нов`, 20, "subscribe_new"),
	p(`нажми.{0,10}здесь`, 20, "click_here"),
}

// Scam job / remote-work offers.
var ScamJobPatterns = []WeightedPattern{
	p(`удалён[кщ]а`, 15, "remote_work"),
	p(`без опыта`, 15, "no_experience"),
	p(`доход.{0,10}в день`, 20, "daily_income"),
	p(`пиши.{0,5}в\s+лс`, 20, "dm_me"),
	p(`напиши.{0,10}личку`, 20, "dm_me2"),
	p(`\bвакансия\b`, 10, "vacancy"),
	p(`зарабатывай`, 15, "earn"),
	p(`заработать`, 15, "earn_money"),
	p(`быстро.{0,10}заработать`, 20, "quick_earn"),
	p(`пассивный.{0,5}доход`, 20, "passive_income"),
	p(`работа.{0,10}дому`, 15, "wfh"),
	p(`\d+\s*[₽$€]\s*в\s*день`, 25, "money_per_day"),
	p(`предлагаю.{0,10}работу`, 20, "offering_job"),
	p(`ищу.{0,10}сотрудник`, 15, "hiring"),
	p(`партнёрство`, 10, "partnership"),
	p(`написать.{0,10}менеджер`, 15, "write_manager"),
	p(`нужны.{0,10}люди`, 20, "need_people"),
	p(`на.{0,10}халтурку`, 20, "odd_jobs"),
	p(`лёгкий.{0,10}онлайн.{0,5}доход`, 20, "easy_online_income"),
	p(`стабильно.{0,10}от.{0,10}\d+`, 15, "stable_from_amount"),
	p(`подойдёт.{0,10}новичкам`, 15, "for_beginners"),
	p(`работаешь.{0,10}когда.{0,10}удобно`, 15, "work_when_convenient"),
	p(`полностью.{0,10}легально`, 15, "fully_legal"),
	p(`хочешь.{0,10}денег`, 20, "want_money"),
	p(`пиши.{0,5}в\s+л_с`, 20, "write_ls"),
	p(`помогу.{0,10}финансами`, 20, "help_with_finances"),
	p(`есть.{0,10}темка`, 20, "have_topic"),
	p(`за пару.{0,10}часов`, 15, "few_hours"),
	p(`\d+к\s*в\s*день`, 25, "k_per_day"),

	// OCR / homoglyph amounts like "14O-23O$ в день" (Latin O as digit).
	p(`\d+[oоOО]\s*[-–]\s*\d+[oоOО0]*\s*[$₽€]\s*в\s*день`, 35, "homoglyph_money_daily"),
	p(`\d+\s*[$₽€]\s*\+\s*.{0,25}в\s*день`, 30, "money_plus_daily"),

	// "No fees from you" + daily-pay job spam.
	p(`без.{0,30}оплат.{0,25}с.{0,15}ваш`, 25, "no_payment_from_you"),
	p(`ставьте.{0,20}\+.{0,25}сюда|кидайте.{0,20}плюс`, 25, "plus_dm_cta"),
	p(`пиши\s*\+\s*сюда`, 30, "write_plus_here"),

	// Ukrainian job / housing scam templates.
	p(`не\s*віддалено`, 40, "ua_not_remote_spam"),
	p(`робота.{0,50}(?:з|\+).{0,25}(?:житл|прожив)|житл(?:о|а).{0,30}(?:надаєм|включен|надає)|вакансії.{0,25}з.{0,15}житл`, 30, "ua_job_housing"),
	p(`в\s*особист|в\s*дірект|особисті\s*повідомлен`, 25, "ua_write_dm"),
	p(`шукаєм.{0,40}(?:працівник|співробітник)|потрібн.{0,30}(?:співробітник|працівник)`, 25, "ua_hiring"),
	p(`допомог.{0,30}(?:з|зі)\s*документ`, 28, "ua_help_documents"),
	p(`зарплат[аи].{0,30}\d+.{0,15}\$.{0,20}тиждень|тиждень.{0,25}\+.{0,20}бонус`, 28, "weekly_usd_salary_spam"),
	p(`робот.{0,20}(?:в|з).{0,20}продаж`, 22, "sales_job_mention"),

	// Warehouse / shift pay spam.
	p(`приглашаем.{0,40}сотрудник.{0,50}склад|сотрудник.{0,40}на\s+склад`, 30, "warehouse_hiring"),
	p(`от\s*\d[\d\s\u00a0]*₽.{0,25}за\s+смену|за\s+смену.{0,40}\d+.{0,20}₽`, 30, "shift_rub_spam"),

	// Vague "easy money" + daily.
	p(`пару.{0,20}часов.{0,35}свободн.{0,40}(?:от\s*\d|каждый\s*день)`, 28, "free_hours_daily_money"),
	p(`каждый\s*день.{0,50}обращайся|обращайся.{0,60}каждый\s*день`, 22, "daily_money_contact"),

	// Odd jobs / "errands" without leaving home.
	p(`поручен.{0,25}на.{0,20}час`, 25, "errands_per_hour"),
	p(`без.{0,20}движен.{0,30}оклад`, 25, "no_movement_salary"),

	// Garage/yard cash-in-hand micro-jobs.
	p(`участк.{0,40}уборк.{0,30}гараж|уборк.{0,30}гараж.{0,50}\d+`, 28, "garage_cleanup_job"),
	p(`\d+.{0,15}р.{0,20}на\s+руки.{0,40}л\s*с|на\s+руки.{0,30}в\s*лс`, 28, "rub_cash_hands_ls"),

	// Fake driver licence / boating licence docs.
	p(`оформл(?:ение|лення).{0,40}водительск`, 30, "fake_driver_license"),
	p(`документы\s+гимс|гимс.{0,25}[🚗⛵]|[🚗⛵].{0,20}гимс`, 30, "gims_docs_spam"),

	// Caps-lock mass hiring + money (needs combo to reach warn).
	p(`нужны\s+люди.{0,150}(?:в\s*день|₽|\$|р\s*\+)`, 35, "need_people_money_combo"),

	// Telegram mini-app / story spam links (t.me/m/...).
	p(`t\.me/m/[a-zA-Z0-9_-]+`, 30, "tme_m_path_spam"),
}

// Ban-tier scams (weight ≥ default ban threshold 80 — one hit ⇒ ban).
var BanPatterns = []WeightedPattern{
	p(`подшабаш|подшабабаш`, 85, "ban_odd_job_slang"),
	p(`наличными\s+на\s+руки.{0,60}отзовитесь\s+в\s+личку|отзовитесь\s+в\s+личку.{0,80}наличными\s+на\s+руки`, 85, "ban_cash_hands_dm"),
	p(`выгодные\s+условия\s+вознаграждения.{0,40}каждый\s+день\s+наличными`, 85, "ban_daily_cash_reward"),
	p(`купить\s+usdt\s+за\s+налич|usdt\s+за\s+наличн`, 85, "ban_usdt_cash"),
	p(`банкомат.{0,80}обмен|обмен.{0,40}usdt`, 85, "ban_usdt_atm_meetup"),
	p(`нужны\s+деньги.{0,60}стартуй`, 85, "ban_need_money_start"),
	p(`пиши\s+и\s+стартуй`, 85, "ban_write_and_start"),
}

// Generic spam call-to-action phrases.
var CTAPatterns = []WeightedPattern{
	p(`только сегодня`, 15, "only_today"),
	p(`осталось.{0,10}\d+.{0,10}мест`, 20, "limited_spots"),
	p(`ограниченное.{0,10}предложение`, 20, "limited_offer"),
	p(`не упусти`, 10, "dont_miss"),
	p(`пиши сейчас|напиши сейчас`, 15, "write_now"),
	p(`пишите`, 10, "write"),
	p(`успей.{0,15}записаться`, 15, "sign_up_now"),
	p(`бесплатно.{0,10}первым`, 15, "free_first"),
}

// Foreign invite links (t.me/+ or joinchat).
var InviteLinkRe = regexp.MustCompile(`(?i)t\.me/\+[a-zA-Z0-9_-]+|t\.me/joinchat/[a-zA-Z0-9_-]+`)

// Short/suspicious URL services.
var ShortURLHostRe = regexp.MustCompile(`(?i)^(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|rebrand\.ly|cutt\.ly|is\.gd|short\.io)$`)
