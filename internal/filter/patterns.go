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
