package app

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CookieAccount 是 cookie 池里的一行：一个 Google 登录态账号。
type CookieAccount struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"user_id"`
	Label      string `json:"label"`
	Cookie     string `json:"cookie"` // 完整串，API 层按需脱敏后再返回
	Status     string `json:"status"`
	Note       string `json:"note"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
	LastOkAt   int64  `json:"last_ok_at"`
	LastError  string `json:"last_error"`
	FailCount  int64  `json:"fail_count"`
	ProxyID    int64  `json:"proxy_id"` // 绑定的出口，0 = 还没绑
}

// splitCookiePairs 把 "k=v; k=v" 拆成键值对。
//
// 按 ";" 切再逐段 TrimSpace，不按 "; " 切：从 DevTools 复制出来的串不一定带空格，
// 而按 "; " 切的话 "SID=a;SAPISID=b" 会整段当成一个键 —— 于是 extractSAPISID
// 取不到值、不发 Authorization 头、请求被上游当匿名处理，用户毫不知情。
//
// 值里可能含 "="（base64 补位），所以只在第一个等号处切。
func splitCookiePairs(cookie string) [][2]string {
	var out [][2]string
	for _, p := range strings.Split(cookie, ";") {
		p = strings.TrimSpace(p)
		if i := strings.Index(p, "="); i > 0 {
			out = append(out, [2]string{p[:i], p[i+1:]})
		}
	}
	return out
}

// cookieValue 从一整串 cookie 里取指定名字的值，取不到返回空串。
func cookieValue(cookie, name string) string {
	for _, kv := range splitCookiePairs(cookie) {
		if kv[0] == name {
			return kv[1]
		}
	}
	return ""
}

// extractSAPISID 从一整串 cookie 里取 SAPISID 的值，取不到返回空串。
func extractSAPISID(cookie string) string {
	return cookieValue(cookie, "SAPISID")
}

// cookieSubset 只留下指定名字的项，顺序跟原串一致。刷新 1PSIDTS 时不能把整串
// 都带上：多带 Chrome DBSC / 其它主机的 cookie 实测会让 RotateCookies 回 401。
func cookieSubset(cookie string, names []string) string {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	var parts []string
	seen := map[string]bool{}
	for _, kv := range splitCookiePairs(cookie) {
		if !want[kv[0]] || kv[1] == "" || seen[kv[0]] {
			continue
		}
		seen[kv[0]] = true
		parts = append(parts, kv[0]+"="+kv[1])
	}
	return strings.Join(parts, "; ")
}

// cookieNames 返回 cookie 串里出现的所有 cookie 名（顺序保留），供 UI 展示。
func cookieNames(cookie string) []string {
	var names []string
	for _, kv := range splitCookiePairs(cookie) {
		names = append(names, kv[0])
	}
	return names
}

// accountAdd 往池里插一条。cookie 必须能取到非空的 SAPISID。
func accountAdd(label, cookie, note string) (int64, error) {
	return accountAddForUser(0, label, cookie, note)
}

func accountAddForUser(userID int64, label, cookie, note string) (int64, error) {
	c, ok := normalizeCookie(cookie, "手工添加的 cookie")
	if !ok {
		return 0, fmt.Errorf("cookie 解析失败：既不是 \"k=v; k=v\" 串，也不是可识别的 JSON")
	}
	if extractSAPISID(c) == "" {
		return 0, fmt.Errorf("cookie 里没有 SAPISID，多半没复制全（需要 gemini.google.com 下的完整 cookie，至少含 SID / HSID / SSID / APISID / SAPISID / __Secure-1PSID）")
	}
	return accountInsertForUser(userID, label, c, note)
}

// accountAdopt 是启动时导入既有配置专用的：不做 SAPISID 检查。
func accountAdopt(label, cookie, note string) (int64, error) {
	return accountAdoptForUser(0, label, cookie, note)
}

func accountAdoptForUser(userID int64, label, cookie, note string) (int64, error) {
	cookie, ok := normalizeCookie(cookie, label)
	if !ok {
		return 0, fmt.Errorf("cookie 解析失败")
	}
	if extractSAPISID(cookie) == "" {
		logf("[cookie] %s 里没有 SAPISID，算不出 SAPISIDHASH 授权头，可能只当匿名处理；先按原样导入，请到面板核对", label)
	}
	return accountInsertForUser(userID, label, cookie, note)
}

func accountInsert(label, cookie, note string) (int64, error) {
	return accountInsertForUser(0, label, cookie, note)
}

func accountInsertForUser(userID int64, label, cookie, note string) (int64, error) {
	cookie = strings.TrimSpace(cookie)
	if cookie == "" {
		return 0, fmt.Errorf("cookie 不能为空")
	}
	return insertID(
		`INSERT INTO accounts(user_id, label, cookie, status, note, created_at) VALUES (?,?,?,?,?,?)`,
		userID, strings.TrimSpace(label), cookie, "enabled", strings.TrimSpace(note), time.Now().Unix())
}

// accountList 返回池里全部账号，按 id 升序。
func accountList() []CookieAccount {
	return accountListForUser(0)
}

func accountListForUser(userID int64) []CookieAccount {
	var query string
	var args []any
	if userID > 0 {
		query = `SELECT id, user_id, label, cookie, status, note, created_at, last_used_at, last_ok_at, last_error, fail_count, proxy_id
		 FROM accounts WHERE user_id=? ORDER BY id`
		args = []any{userID}
	} else {
		query = `SELECT id, user_id, label, cookie, status, note, created_at, last_used_at, last_ok_at, last_error, fail_count, proxy_id
		 FROM accounts ORDER BY id`
	}
	rows, err := getDB().Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []CookieAccount
	for rows.Next() {
		var a CookieAccount
		if err := rows.Scan(&a.ID, &a.UserID, &a.Label, &a.Cookie, &a.Status, &a.Note,
			&a.CreatedAt, &a.LastUsedAt, &a.LastOkAt, &a.LastError, &a.FailCount, &a.ProxyID); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out
}

// accountByID 按 id 取一条，取不到返回 nil。
func accountByID(id int64) *CookieAccount {
	var a CookieAccount
	err := getDB().QueryRow(
		`SELECT id, user_id, label, cookie, status, note, created_at, last_used_at, last_ok_at, last_error, fail_count, proxy_id
		 FROM accounts WHERE id=?`, id).
		Scan(&a.ID, &a.UserID, &a.Label, &a.Cookie, &a.Status, &a.Note,
			&a.CreatedAt, &a.LastUsedAt, &a.LastOkAt, &a.LastError, &a.FailCount, &a.ProxyID)
	if err != nil {
		return nil
	}
	return &a
}

// accountDelete 删除一条。
func accountDelete(id int64) error {
	_, err := getDB().Exec(`DELETE FROM accounts WHERE id=?`, id)
	return err
}

// accountSetStatus 改状态（enabled / disabled）。
func accountSetStatus(id int64, status string) error {
	if status != "enabled" && status != "disabled" {
		return fmt.Errorf("非法状态 %q", status)
	}
	_, err := getDB().Exec(`UPDATE accounts SET status=? WHERE id=?`, status, id)
	return err
}

// accountUpdateMeta 改 label / note（不动 cookie 本身）。
func accountUpdateMeta(id int64, label, note string) error {
	_, err := getDB().Exec(`UPDATE accounts SET label=?, note=? WHERE id=?`,
		strings.TrimSpace(label), strings.TrimSpace(note), id)
	return err
}

// accountCount 返回 (总数, enabled 数)。
func accountCount() (int, int) {
	return accountCountForUser(0)
}

func accountCountForUser(userID int64) (int, int) {
	var total, enabled int
	if userID > 0 {
		_ = getDB().QueryRow(`SELECT COUNT(*), SUM(CASE WHEN status='enabled' THEN 1 ELSE 0 END) FROM accounts WHERE user_id=?`, userID).
			Scan(&total, &enabled)
	} else {
		_ = getDB().QueryRow(`SELECT COUNT(*), SUM(CASE WHEN status='enabled' THEN 1 ELSE 0 END) FROM accounts`).
			Scan(&total, &enabled)
	}
	return total, enabled
}

func hasCookieForUser(userID int64) bool {
	_, enabled := accountCountForUser(userID)
	return enabled > 0
}

// kv 里记迁移/播种状态的键。
const (
	kvLegacyCookieDone = "legacy_single_cookie_migrated"
	kvSeededCookieID   = "seeded_cookie_id"
	kvSeededCookieVal  = "seeded_cookie_value"
)

// seedCookiesFromConfig 把启动参数和历史遗留的单 cookie 并进 cookie 池。
//
// cookie 原来也有两个入口：cookie 池，和「设置」页那个池空时才用的单 cookie 输入
// （值存 kv 的 google_cookie，或来自 --cookie-file）。跟静态代理同一个毛病 ——
// 单 cookie 路径返回的账号 ID 是 0，而 markAccountResult 开头就是 id<=0 直接返回，
// 于是**健康度一个字都不写**：fail_count 恒为 0、last_ok_at 恒为空，也没有轮转。
//
//   - kv 里的 google_cookie：一次性迁入，用独立标记记"迁过了"，原值不动
//   - cfg.CookieFile（--cookie-file）：声明式跟随，内容变了替换同一条记录
func seedCookiesFromConfig() {
	migrateLegacyCookie()
	syncSeededCookieFile()
}

// migrateLegacyCookie 一次性把 kv 里遗留的单 cookie 搬进池子。
// 三条保命规则：走 accountAdopt 不做 SAPISID 校验（旧路径不校验，升级不该改变
// 可用性）、入池成功才标记完成、不去动 kv 里原来的值（回滚到旧版仍可用）。
func migrateLegacyCookie() {
	if kvGet(kvLegacyCookieDone) == "1" {
		return
	}
	raw := strings.TrimSpace(kvGet("google_cookie"))
	if raw == "" {
		_ = kvSet(kvLegacyCookieDone, "1")
		return
	}
	cookie, ok := normalizeCookie(raw, "「设置」页的单 cookie")
	if !ok {
		return
	}
	if !poolHasCookie(cookie) {
		if _, err := accountAdopt("原单 cookie", cookie, "从「设置」页迁入"); err != nil {
			logf("[cookie] 「设置」页的单 cookie 迁入池子失败，原值保留、下次启动重试: %v", err)
			return
		}
		logf("[cookie] 「设置」页的单 cookie 已迁入 cookie 池")
	}
	_ = kvSet(kvLegacyCookieDone, "1")
}

// syncSeededCookieFile 让池子里跟着 --cookie-file 走一条记录。
//
// 跟 --proxy 同一套：文件内容变了就撤下旧的那条再建新的，而不是又加一条。
// 按内容去重挡不住这个 —— 定期轮换 cookie.txt 的部署会一次次往池子里堆死 cookie，
// 而它们仍然 enabled，仍然参与轮转，于是每 N 个请求就有一个注定失败。
// 内容没变时完全不碰池子，面板上的增删改停用都以面板为准。
func syncSeededCookieFile() {
	var cur string
	if cfg.CookieFile != "" {
		data, err := os.ReadFile(cfg.CookieFile)
		if err != nil {
			// 读不到就当没配过：宁可保持现状，也不能因为容器少挂一个卷
			// 就把用户在用的 cookie 撤下来。
			logf("[cookie] 读不了 --cookie-file %s，池子保持不变: %v", cfg.CookieFile, err)
			return
		}
		cur = strings.TrimSpace(string(data))
	}
	if cur != "" {
		if c, ok := normalizeCookie(cur, "--cookie-file"); ok {
			cur = c
		} else {
			return
		}
	}

	prev := kvGet(kvSeededCookieVal)
	if cur == prev {
		return
	}
	dropSeededCookie(prev)
	if cur == "" {
		_ = kvSet(kvSeededCookieVal, "")
		_ = kvSet(kvSeededCookieID, "")
		logf("[cookie] --cookie-file 已移除，对应的池子记录一并撤下")
		return
	}
	if poolHasCookie(cur) {
		_ = kvSet(kvSeededCookieVal, cur)
		_ = kvSet(kvSeededCookieID, "")
		return
	}
	id, err := accountAdopt("cookie-file", cur, "来自 --cookie-file")
	if err != nil {
		logf("[cookie] --cookie-file 入池失败: %v", err)
		return
	}
	_ = kvSet(kvSeededCookieVal, cur)
	_ = kvSet(kvSeededCookieID, strconv.FormatInt(id, 10))
	logf("[cookie] --cookie-file 的 cookie 已加入 cookie 池")
}

// dropSeededCookie 撤掉上一次由 --cookie-file 建的那条。
// 只在内容还是我们写进去的那份时才删——用户在面板改过就说明他接管了。
func dropSeededCookie(prevCookie string) {
	idStr := kvGet(kvSeededCookieID)
	if idStr == "" || prevCookie == "" {
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		return
	}
	for _, a := range accountList() {
		if a.ID == id {
			if a.Cookie == prevCookie {
				if err := accountDelete(id); err != nil {
					logf("[cookie] 撤下旧的 --cookie-file 记录失败: %v", err)
				}
			}
			return
		}
	}
}

// 面板逐项填写模式列出的 cookie，同时也是拼串时的固定顺序。
// 顺序必须确定：同一份 cookie 若因键顺序不同拼出两种串，按内容去重就失效了。
var cookieTemplateOrder = []string{
	"SID", "HSID", "SSID", "APISID", "SAPISID", "__Secure-1PSID", "__Secure-1PSIDTS",
}

// normalizeCookie 把各种输入形态归一化成池子要的裸 "k=v; k=v" 串。
//
// 吃三种：
//   - 裸串，原样返回
//   - 旧单 cookie 路径的 {"cookie":"k=v; k=v","sapisid":"..."}
//   - 面板逐项模式的 {"SID":"a","SAPISID":"b",...}
//
// 不归一化的话池子里会存进一整段 JSON，SAPISID 提取和后续请求全错。
func normalizeCookie(raw, who string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "{") {
		return raw, true
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		logf("[cookie] %s 是 JSON 但解析失败，跳过: %v", who, err)
		return "", false
	}
	if c, ok := m["cookie"].(string); ok && strings.TrimSpace(c) != "" {
		return strings.TrimSpace(c), true
	}

	str := func(k string) string {
		s, _ := m[k].(string)
		return strings.TrimSpace(s)
	}
	var parts []string
	inTemplate := map[string]bool{}
	for _, k := range cookieTemplateOrder {
		inTemplate[k] = true
		if v := str(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	// 用户从 DevTools 多复制几项进来不能丢，附在模板字段后面按名字排序
	var extra []string
	for k := range m {
		if !inTemplate[k] && k != "sapisid" && str(k) != "" {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		parts = append(parts, k+"="+str(k))
	}
	if len(parts) == 0 {
		logf("[cookie] %s 是 JSON 但一项非空值都没有，跳过", who)
		return "", false
	}
	return strings.Join(parts, "; "), true
}

func poolHasCookie(cookie string) bool {
	for _, a := range accountList() {
		if a.Cookie == cookie {
			return true
		}
	}
	return false
}

// pickMu 把「SELECT 最久未用的号 + UPDATE 标记它刚用过」串成原子操作。
// 不加锁时两个并发请求会 SELECT 到同一个"最久未用"的号、各自 UPDATE，于是同一瞬间
// 双双用它，轮转形同虚设（CLAUDE.md 记的已知缺陷）。本进程内一把锁就够——限流器、
// 轮转调度、代理池都是进程内状态，这个反代天生单实例，不存在跨进程并发挑号；也就
// 不必为此上跨方言的事务/行锁（sqlite 无 FOR UPDATE、mysql 无 RETURNING，那条路
// 全是方言分支）。挑号只是一次极快的 SELECT+UPDATE，串行化的争用可忽略。
var pickMu sync.Mutex

// pickCookieAccount 从池里挑一个 enabled 账号，按 last_used_at 最久优先，
// 挑中后立刻把 last_used_at 记为现在（下次轮到别人）。池空返回 (nil,false)。
func pickCookieAccount() (*CookieAccount, bool) {
	return pickCookieAccountForUserExcept(0, nil)
}

// pickCookieAccountExcept 同上，但跳过本次已经试过的账号。
func pickCookieAccountExcept(skip map[int64]bool) (*CookieAccount, bool) {
	return pickCookieAccountForUserExcept(0, skip)
}

// pickCookieAccountForUser 从指定用户的 cookie 池里挑一个 enabled 账号。
func pickCookieAccountForUser(userID int64) (*CookieAccount, bool) {
	return pickCookieAccountForUserExcept(userID, nil)
}

// pickCookieAccountForUserExcept 同上，但跳过已试过的账号。
// 当 userID > 0 时，只在 user_id = userID 的账号中挑选，绝对隔离，杜绝串用。
func pickCookieAccountForUserExcept(userID int64, skip map[int64]bool) (*CookieAccount, bool) {
	pickMu.Lock()
	defer pickMu.Unlock()

	var query string
	var args []any
	if userID > 0 {
		query = `SELECT id, user_id, label, cookie, status, note, created_at, last_used_at, last_ok_at, last_error, fail_count, proxy_id
		 FROM accounts WHERE status='enabled' AND user_id=? ORDER BY fail_count ASC, last_used_at ASC, id ASC`
		args = []any{userID}
	} else {
		query = `SELECT id, user_id, label, cookie, status, note, created_at, last_used_at, last_ok_at, last_error, fail_count, proxy_id
		 FROM accounts WHERE status='enabled' ORDER BY fail_count ASC, last_used_at ASC, id ASC`
	}

	rows, err := getDB().Query(query, args...)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	for rows.Next() {
		var a CookieAccount
		if err := rows.Scan(&a.ID, &a.UserID, &a.Label, &a.Cookie, &a.Status, &a.Note,
			&a.CreatedAt, &a.LastUsedAt, &a.LastOkAt, &a.LastError, &a.FailCount, &a.ProxyID); err != nil {
			continue
		}
		if skip != nil && skip[a.ID] {
			continue
		}
		_, _ = getDB().Exec(`UPDATE accounts SET last_used_at=? WHERE id=?`, time.Now().Unix(), a.ID)
		return &a, true
	}
	return nil, false
}

// markCookieByStatus 按上游返回回写 cookie 健康度。
//
// 只把明确的鉴权失败（401/403）算作 cookie 的错。网络错误、代理失败、302 → sorry
// （IP 被 Google 拦）一律不计——实测住宅代理出口退化率高达 75%，把这些算进
// fail_count 会让它变成代理噪音，好 cookie 会被误伤成"失败最多"。
//
// statusCode 为 0 表示压根没拿到响应（网络层失败）。
func markCookieByStatus(id int64, statusCode int, errStr string) {
	switch {
	case statusCode == 200:
		markAccountResult(id, true, "")
	case statusCode == 401 || statusCode == 403:
		markAccountResult(id, false, errStr)
	default:
		// 其余情况责任不在 cookie，不动它的健康度
	}
}

// markAccountResult 请求结束后回写结果：成功清零 fail_count 并记 last_ok_at；
// 失败累加 fail_count 并记 last_error。
//
// 注意 last_ok_at 的语义是"这个 cookie 参与的请求成功过"，**不等于"cookie 仍然
// 有效"**：cookie 过期后 Gemini 不报错，只是把你当匿名用户，纯文本请求照样 200。
// 要真正验有效性，最省事的判据是请求 gemini-3.1-pro：cookie 有效时服务端回报
// "3.1 Pro" 并带思考链，失效时静默降级成 3.5 Flash-Lite。（xsrf.go 取 token 时
// 若页面里没有 SNlM0e，也会当场判定 cookie 失效。）
func markAccountResult(id int64, ok bool, errStr string) {
	if id <= 0 {
		return
	}
	if ok {
		_, _ = getDB().Exec(
			`UPDATE accounts SET last_ok_at=?, fail_count=0, last_error='' WHERE id=?`,
			time.Now().Unix(), id)
		return
	}
	_, _ = getDB().Exec(
		`UPDATE accounts SET fail_count=fail_count+1, last_error=? WHERE id=?`,
		truncate(errStr, 200), id)
	autoDisableIfDead(id)
}

// maxCookieAuthFailures 是连续几次鉴权失败之后自动停用账号。
//
// 只有 401/403 会累加 fail_count（见 markCookieByStatus），网络错误和被 Google 拦
// 都不算，所以连着 3 次基本等于 cookie 真的没了。取 3 不取 1：偶发的 XSRF 页面抖动
// 也会走到这条路上，一次就停用会误伤。
const maxCookieAuthFailures = 3

// autoDisableIfDead 把连续失败到头的账号停用。
//
// 为什么要自动停：挑号是 `ORDER BY fail_count ASC` ——坏号排在最后，但**池子里只剩
// 坏号时它照样会被选中**，于是每个请求都要把它试一遍才轮到报错。而 fail_count 只有
// 成功才清零，死号永远不会自己好，等于让每个请求都为它付一次 XSRF 往返。
//
// 停用而不是删除：cookie 是用户导入的数据，判断可能出错（比如出口连续被拦也可能
// 表现成鉴权失败），留着让用户在面板上看到并自己决定。
func autoDisableIfDead(id int64) {
	var fails int64
	var status string
	err := getDB().QueryRow(`SELECT fail_count, status FROM accounts WHERE id=?`, id).
		Scan(&fails, &status)
	if err != nil || status != "enabled" || fails < maxCookieAuthFailures {
		return
	}
	if _, err := getDB().Exec(
		`UPDATE accounts SET status='disabled' WHERE id=? AND status='enabled'`, id); err == nil {
		logf("[cookie] 账号 #%d 连续 %d 次鉴权失败，已自动停用", id, fails)
	}
}

// CookieCheck 是一次 cookie 有效性检测的结果。
type CookieCheck struct {
	OK        bool   `json:"ok"`
	Detail    string `json:"detail"`
	ProxyName string `json:"proxy_name"`
	TookMs    int64  `json:"took_ms"`
}

// checkAccountCookie 判断一条 cookie 还有没有登录态。
//
// 判据是 /app 页面里有没有 SNlM0e：cookie 失效时 Gemini 不报错，只是把你当匿名
// 用户，纯文本请求照样 200 —— 所以不能拿"请求成功"当有效性判据。这个页面没有
// SNlM0e 就说明服务端没认这个登录态。
//
// 只抓页面，不发对话，不消耗生成配额。
func checkAccountCookie(a CookieAccount) CookieCheck {
	t0 := time.Now()
	picked, ok, err := acquireSlot(a.ProxyID)
	if !ok {
		return CookieCheck{Detail: "No egress available: " + err.Error()}
	}
	defer releaseSlot(picked.ID)
	proxyURL := picked.URL
	name := picked.Name
	if name == "" {
		name = "Direct"
	}

	// 先作废缓存，否则可能拿到几分钟前的旧结论，检测就没意义了
	invalidateXSRF(a.Cookie)
	_, err = getXSRF(a.Cookie, proxyURL)
	took := time.Since(t0).Milliseconds()
	if err != nil {
		markAccountResult(a.ID, false, err.Error())
		return CookieCheck{Detail: explainCookieFailure(err), ProxyName: name, TookMs: took}
	}
	markAccountResult(a.ID, true, "")
	detail := "Session is valid"
	if extractSAPISID(a.Cookie) == "" {
		detail += ", but missing SAPISID (cannot generate auth header; some endpoints will be treated as anonymous)"
	}
	return CookieCheck{OK: true, Detail: detail, ProxyName: name, TookMs: took}
}

// explainCookieFailure formats low-level errors into human-readable diagnostic conclusions.
func explainCookieFailure(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no SNlM0e"):
		return "Cookie expired: page loads but session is invalid; requests will be treated as anonymous"
	case strings.Contains(msg, "HTTP 302"):
		return "Cookie invalid: redirected to login page"
	case strings.Contains(msg, "HTTP 429"), strings.Contains(msg, "sorry"):
		return "Egress rate-limited by upstream, try another proxy (not a cookie issue)"
	default:
		return "Check failed: " + msg
	}
}

// bindAccountProxy 记住这个账号这次用的出口，下次优先复用。
func bindAccountProxy(accountID, proxyID int64) {
	if accountID <= 0 {
		return
	}
	_, _ = getDB().Exec(`UPDATE accounts SET proxy_id=? WHERE id=?`, proxyID, accountID)
}

// accountDisplayName 面板/记录里显示的账号名，没填标签就用 #id。
func accountDisplayName(a *CookieAccount) string {
	if a.Label != "" {
		return a.Label
	}
	return fmt.Sprintf("#%d", a.ID)
}

// mergeSetCookie 把响应下发的 Set-Cookie 合并进现有 cookie 串。
//
// 服务端几乎每个响应都在刷新 SIDCC / __Secure-1PSIDCC / __Secure-3PSIDCC
// （2 小时抓包里 batchexecute 就刷了 468 次），浏览器收下再带回去。一直发旧值的
// 客户端会被判定为过期会话 —— 实测不合并的号活一两小时就失效。
//
// 顺序保持原样、新键追加在后：cookie 顺序本身不影响语义，但保持稳定能让
// poolHasCookie 那类按内容比对的地方不至于每次都认成新值。
func mergeSetCookie(cookie string, setCookie []string) string {
	if len(setCookie) == 0 {
		return cookie
	}
	updates := map[string]string{}
	for _, sc := range setCookie {
		first := strings.TrimSpace(strings.SplitN(sc, ";", 2)[0])
		i := strings.Index(first, "=")
		if i <= 0 {
			continue
		}
		name, val := first[:i], first[i+1:]
		// 删除指令（过期时间在过去 + 空值）不能当成新值写进去
		if val == "" && strings.Contains(strings.ToLower(sc), "expires=thu, 01 jan 1970") {
			continue
		}
		updates[name] = val
	}
	if len(updates) == 0 {
		return cookie
	}
	var parts []string
	seen := map[string]bool{}
	for _, kv := range splitCookiePairs(cookie) {
		seen[kv[0]] = true
		if v, ok := updates[kv[0]]; ok {
			parts = append(parts, kv[0]+"="+v)
			continue
		}
		parts = append(parts, kv[0]+"="+kv[1])
	}
	for name, val := range updates {
		if !seen[name] {
			parts = append(parts, name+"="+val)
		}
	}
	return strings.Join(parts, "; ")
}

// cookieIdentity 取能代表"这是哪个账号"的那几项。
//
// SAPISID 用来算授权头、__Secure-1PSID 是会话主键，两者都不随刷新变化（2 小时
// 抓包里 0 次变动，变的只有 *SIDCC 和 *SIDTS 那两族）。所以它们变了就说明这份
// cookie 已经不是原来那个账号了。
func cookieIdentity(cookie string) string {
	var sapisid, psid string
	for _, kv := range splitCookiePairs(cookie) {
		switch kv[0] {
		case "SAPISID":
			sapisid = kv[1]
		case "__Secure-1PSID":
			psid = kv[1]
		}
	}
	return sapisid + "|" + psid
}

// updateAccountCookie 把刷新后的 cookie 写回账号。
//
// 写之前先比对身份：合并 Set-Cookie 时上游理论上可以把整套会话换掉（比如响应里
// 带了另一个账号的 SID），照单全收就等于把 A 号的凭据写进 B 号那一行。之后这个号
// 在面板上显示的还是原来的标签，实际发出去的却是别人的会话，而且**完全静默**。
// 身份对不上就不写，宁可让这次刷新白费。
func updateAccountCookie(id int64, cookie string) {
	if id <= 0 || cookie == "" {
		return
	}
	var cur string
	if err := getDB().QueryRow(`SELECT cookie FROM accounts WHERE id=?`, id).Scan(&cur); err == nil {
		if got, want := cookieIdentity(cookie), cookieIdentity(cur); got != want {
			logf("[cookie] 账号 #%d 的刷新结果身份对不上，已丢弃不写回", id)
			return
		}
	}
	_, _ = getDB().Exec(`UPDATE accounts SET cookie=? WHERE id=?`, cookie, id)
}
