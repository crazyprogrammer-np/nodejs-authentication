exports.home = (req, res) => {
    data = {
        title: 'Home Page',
        layout: './layouts/layout',
        successMessage: req.flash('success'),
        errorMessage: req.flash('error'),
        user: req.user
    }
    return res.status(200).render('dashboard/home', data);
}