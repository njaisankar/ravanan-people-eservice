from django.db import models
from django.contrib.auth.models import User
import datetime
from django import utils


# Create your models here.

class AdminProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile = models.TextField(default="",null=True,blank=True)

    def __str__(self):
        return self.mobile

class ServiceLinks(models.Model):
    ration_1_title = models.TextField(default="",null=True,blank=True)
    ration_1_titleLink = models.TextField(default="",null=True,blank=True)
    
    ration_2_title = models.TextField(default="",null=True,blank=True)
    ration_2_titleLink = models.TextField(default="",null=True,blank=True)
    
    ration_3_title = models.TextField(default="",null=True,blank=True)
    ration_3_titleLink = models.TextField(default="",null=True,blank=True)
    
    ration_4_title = models.TextField(default="",null=True,blank=True)
    ration_4_titleLink = models.TextField(default="",null=True,blank=True)

#-------------------------------------------------------------------------

    aadhar_1_title = models.TextField(default="",null=True,blank=True)
    aadhar_1_titleLink = models.TextField(default="",null=True,blank=True)
    
    aadhar_2_title = models.TextField(default="",null=True,blank=True)
    aadhar_2_titleLink = models.TextField(default="",null=True,blank=True)
    
    aadhar_3_title = models.TextField(default="",null=True,blank=True)
    aadhar_3_titleLink = models.TextField(default="",null=True,blank=True)
    
    aadhar_4_title = models.TextField(default="",null=True,blank=True)
    aadhar_4_titleLink = models.TextField(default="",null=True,blank=True)


#-------------------------------------------------------------------------

    pan_1_title = models.TextField(default="",null=True,blank=True)
    pan_1_titleLink = models.TextField(default="",null=True,blank=True)
    
    pan_2_title = models.TextField(default="",null=True,blank=True)
    pan_2_titleLink = models.TextField(default="",null=True,blank=True)
    
    pan_3_title = models.TextField(default="",null=True,blank=True)
    pan_3_titleLink = models.TextField(default="",null=True,blank=True)
    
    pan_4_title = models.TextField(default="",null=True,blank=True)
    pan_4_titleLink = models.TextField(default="",null=True,blank=True)


#-------------------------------------------------------------------------

    welfar_1_title = models.TextField(default="",null=True,blank=True)
    welfar_1_titleLink = models.TextField(default="",null=True,blank=True)
    
    welfar_2_title = models.TextField(default="",null=True,blank=True)
    welfar_2_titleLink = models.TextField(default="",null=True,blank=True)
    
    welfar_3_title = models.TextField(default="",null=True,blank=True)
    welfar_3_titleLink = models.TextField(default="",null=True,blank=True)
    
    welfar_4_title = models.TextField(default="",null=True,blank=True)
    welfar_4_titleLink = models.TextField(default="",null=True,blank=True)


#-------------------------------------------------------------------------

    
    voter_1_title = models.TextField(default="",null=True,blank=True)
    voter_1_titleLink = models.TextField(default="",null=True,blank=True)
    
    voter_2_title = models.TextField(default="",null=True,blank=True)
    voter_2_titleLink = models.TextField(default="",null=True,blank=True)
    
    voter_3_title = models.TextField(default="",null=True,blank=True)
    voter_3_titleLink = models.TextField(default="",null=True,blank=True)
    
    voter_4_title = models.TextField(default="",null=True,blank=True)
    voter_4_titleLink = models.TextField(default="",null=True,blank=True)



#-------------------------------------------------------------------------

    other_1_title = models.TextField(default="",null=True,blank=True)
    other_1_titleLink = models.TextField(default="",null=True,blank=True)
    
    other_2_title = models.TextField(default="",null=True,blank=True)
    other_2_titleLink = models.TextField(default="",null=True,blank=True)
    
    other_3_title = models.TextField(default="",null=True,blank=True)
    other_3_titleLink = models.TextField(default="",null=True,blank=True)
    
    other_4_title = models.TextField(default="",null=True,blank=True)
    other_4_titleLink = models.TextField(default="",null=True,blank=True)

    def __str__(self):
        return "Service Links"

class Service(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    jobno = models.TextField(default="",null=True,blank=True)
    jobtit = models.TextField(default="",null=True,blank=True)
    job = models.TextField(default="",null=True,blank=True)
    ithura  = models.TextField(default="",null=True,blank=True)
    shopno = models.TextField(default="",null=True,blank=True)
    refno = models.TextField(default="",null=True,blank=True)
    refdoc = models.FileField(upload_to=f'User/Documents/',default='default.png',null=True,blank=True)
    amount = models.TextField(default="",null=True,blank=True)
    bname = models.TextField(default="",null=True,blank=True)
    regmob = models.TextField(default="",null=True,blank=True)
    conmob = models.TextField(default="",null=True,blank=True)
    email = models.TextField(default="",null=True,blank=True)
    ondriyam = models.TextField(default="",null=True,blank=True)
    other = models.TextField(default="",null=True,blank=True)
    oor = models.TextField(default="",null=True,blank=True)
    oratchi = models.TextField(default="",null=True,blank=True)
    theru = models.TextField(default="",null=True,blank=True)
    status = models.TextField(default="Processing",null=True,blank=True)
    date = models.DateTimeField(default = utils.timezone.now)
    approve = models.BooleanField(default=False)
    lstUser = models.TextField(default="",null=True,blank=True)

    def __str__(self):
        return self.bname


class IndexPage(models.Model):
    title = models.TextField(default="",null=True,blank=True)
    SubTitle = models.TextField(default="",null=True,blank=True)

    smallTitle = models.TextField(default="",null=True,blank=True)
    smallTitleSub = models.TextField(default="",null=True,blank=True)
    smallTitle_content_1 = models.TextField(default="",null=True,blank=True)
    smallTitle_content_2 = models.TextField(default="",null=True,blank=True)

    smallTitle_2 = models.TextField(default="",null=True,blank=True)
    smallTitleSub_2 = models.TextField(default="",null=True,blank=True)
    smallTitle_content_1_2 = models.TextField(default="",null=True,blank=True)
    smallTitle_content_2_2 = models.TextField(default="",null=True,blank=True)

    smallTitle_3 = models.TextField(default="",null=True,blank=True)
    smallTitleSub_3 = models.TextField(default="",null=True,blank=True)
    smallTitle_content_1_3 = models.TextField(default="",null=True,blank=True)
    smallTitle_content_2_3 = models.TextField(default="",null=True,blank=True)

    vrt_block_1 = models.TextField(default="",null=True,blank=True)
    vrt_block_1_content = models.TextField(default="",null=True,blank=True)
    vrt_block_2 = models.TextField(default="",null=True,blank=True)
    vrt_block_2_content = models.TextField(default="",null=True,blank=True)
    vrt_block_3 = models.TextField(default="",null=True,blank=True)
    vrt_block_3_content = models.TextField(default="",null=True,blank=True)

    mid_content = models.TextField(default="",null=True,blank=True)
    mid_content_sub = models.TextField(default="",null=True,blank=True)

    bottom_content = models.TextField(default="",null=True,blank=True)


    addressTitle = models.TextField(default="",null=True,blank=True)
    address_1 = models.TextField(default="",null=True,blank=True)
    address_2 = models.TextField(default="",null=True,blank=True)
    address_3 = models.TextField(default="",null=True,blank=True)

    facebook = models.TextField(default="",null=True,blank=True)
    youtube = models.TextField(default="",null=True,blank=True)
    twitter = models.TextField(default="",null=True,blank=True)
    whatsapp = models.TextField(default="",null=True,blank=True)

    cover_1 = models.FileField(upload_to=f'User/Documents/index_page/cover',default='User/Documents/index_page/cover/slide-1.jpg',null=True,blank=True)
    cover_2 = models.FileField(upload_to=f'User/Documents/index_page/cover',default='User/Documents/index_page/cover/slide-2.jpg',null=True,blank=True)
    cover_3 = models.FileField(upload_to=f'User/Documents/index_page/cover',default='User/Documents/index_page/cover/slide-3.jpg',null=True,blank=True)

    news_1 = models.FileField(upload_to=f'User/Documents/index_page/News',default='User/Documents/index_page/News/news.png',null=True,blank=True)
    news_2 = models.FileField(upload_to=f'User/Documents/index_page/News',default='User/Documents/index_page/News/news.png',null=True,blank=True)
    news_3 = models.FileField(upload_to=f'User/Documents/index_page/News',default='User/Documents/index_page/News/news.png',null=True,blank=True)


    def __str__(self):
        return "Index page content"