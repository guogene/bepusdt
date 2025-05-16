package web

import (
	"html/template"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/v03413/bepusdt/app/conf"
	"github.com/v03413/bepusdt/app/log"
	"github.com/v03413/bepusdt/static"
)

func Start() {
	gin.SetMode(gin.ReleaseMode)

	var listen = conf.GetListen()
	var engine = loadStatic(gin.New())

	{
		engine.Use(gin.LoggerWithWriter(log.GetWriter()), gin.Recovery())
		engine.Use(func(ctx *gin.Context) {
			ctx.Writer.Header().Set("Payment-Gateway", "https://github.com/v03413/bepusdt")
		})
		engine.GET("/", func(c *gin.Context) {
			c.HTML(200, "index.html", gin.H{"title": "一款更易用的USDT收款网关", "url": "https://github.com/v03413/bepusdt"})
		})
	}

	payGrp := engine.Group("/pay")
	{
		payGrp.GET("/checkout-counter/:trade_id", checkoutCounter)
		payGrp.GET("/check-status/:trade_id", checkStatus)
	}

	orderGrp := engine.Group("/api/v1/order")
	{
		orderGrp.Use(signVerify)
		orderGrp.POST("/create-transaction", createTransaction)
		orderGrp.POST("/cancel-transaction", cancelTransaction)
	}

	// 易支付兼容
	{
		engine.POST("/submit.php", epaySubmit)
		engine.GET("/submit.php", epaySubmit)
	}

	// 管理后台页面
	// engine.GET("/admin/login", func(c *gin.Context) {
	// 	c.File("views/admin/login.html")
	// })
	// engine.GET("/admin/dashboard", func(c *gin.Context) {
	// 	c.File("admin/dashboard.html")
	// })

	// 管理后台API
	adminGrp := engine.Group("/api/admin")
	{
		adminGrp.POST("/login", AdminLogin)

		// 需要登录验证的接口
		adminGrp.Use(AdminAuth())
		{
			adminGrp.GET("/orders", GetOrders)
			adminGrp.GET("/records", GetRecords)
		}
	}

	log.Info("WEB尝试启动 Listen: ", listen)
	go func() {
		err := engine.Run(listen)
		if err != nil {

			log.Error("Web启动失败", err)
		}
	}()
}

// 加载静态资源
func loadStatic(engine *gin.Engine) *gin.Engine {
	var staticPath = conf.GetStaticPath()
	if staticPath != "" {
		engine.Static("/img", conf.GetStaticPath()+"/img")
		engine.Static("/css", conf.GetStaticPath()+"/css")
		engine.Static("/js", conf.GetStaticPath()+"/js")
		engine.LoadHTMLGlob(conf.GetStaticPath() + "/views/*")
		// engine.LoadHTMLGlob(conf.GetStaticPath() + "/views/admin/*")

		return engine
	}

	engine.StaticFS("/img", http.FS(subFs(static.Img, "img")))
	engine.StaticFS("/css", http.FS(subFs(static.Css, "css")))
	engine.StaticFS("/js", http.FS(subFs(static.Js, "js")))
	engine.StaticFS("/admin", http.FS(subFs(static.Views, "views/admin")))
	engine.SetHTMLTemplate(template.Must(template.New("").ParseFS(static.Views, "views/*.html")))

	return engine
}

func subFs(src fs.FS, dir string) fs.FS {
	subFS, _ := fs.Sub(src, dir)

	return subFS
}
